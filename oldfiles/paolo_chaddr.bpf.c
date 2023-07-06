// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "hike_vm.h"
#include "parse_helpers.h"
#include "paolo_kroute.h"

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#define HIKE_PROG_NAME paolo_chaddr

bpf_map(chaddr, HASH, __be16, struct in6_addr, 2);

static __always_inline void ipv6_addr_set(struct in6_addr *addr,
                                          __be32 w1, __be32 w2,
                                          __be32 w3, __be32 w4)
{
        addr->in6_u.u6_addr32[0] = w1;
        addr->in6_u.u6_addr32[1] = w2;
        addr->in6_u.u6_addr32[2] = w3;
        addr->in6_u.u6_addr32[3] = w4;
}


HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
        struct in6_addr *daddr;
        struct ipv6hdr *ip6h;
        __be16 key = 0;
	//int rc;

        hike_pr_debug("init paolo_chaddr");

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        hike_pr_debug("pre paolo_chaddr");

        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*ip6h));

	if (unlikely(!ip6h))
		goto drop;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

        key = 2; //select dst address
        daddr = bpf_map_lookup_elem(&chaddr, &key);

        if (unlikely(!daddr))
        {
                hike_pr_err("cannot read dst addr map");
                goto drop;
        }

        ip6h->daddr = *daddr;

        //ipv6_addr_set(&ip6h->daddr, bpf_ntohl(0x20010db8), bpf_ntohl(0x04000300), bpf_ntohl(0x02000100), 0);
        /*ipv6_addr_set(&ip6h->daddr, 0xb80d0120, 0x00030004, 0x00010002, 0);*/


        hike_pr_debug("post paolo_chaddr, addr");

	return HIKE_XDP_VM;

drop:
        hike_pr_debug("DROP paolo_chaddr");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, chaddr);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
