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

#define HIKE_PROG_NAME paolo_ip6_dst_filter
#define HIKE_MAPS_NAME ip6_dst

//#ifndef memcmp
//#define memcmp(a, b, n) __builtin_memcmp((a), (b), (n))
//#endif


bpf_map(HIKE_MAPS_NAME, HASH, __be16, struct in6_addr, 2);

HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
        struct in6_addr *daddr;
        struct ipv6hdr *ip6h;
        __be16 key = 0;
	//int rc;

        hike_pr_debug("init paolo_ip6_dst_filter");

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        hike_pr_debug("pre paolo_ip6_dst_filter");

        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*ip6h));

	if (unlikely(!ip6h))
		goto drop;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

        //key = 2; //select dst address
        daddr = bpf_map_lookup_elem(&ip6_dst, &key);

        if (unlikely(!daddr))
        {
                hike_pr_err("cannot read dst addr map");
                goto drop;
        }

        int i;
        struct in6_addr *addr;

        addr = &ip6h->daddr;

        for (i = 0; i < 16; ++i) {
                if (addr->s6_addr[i] != daddr->s6_addr[i])
                        return XDP_PASS;
        }

        return HIKE_XDP_VM;


//	if (memcmp(&ip6h->daddr, daddr, sizeof(ip6h->daddr)) != 0)
//            return HIKE_XDP_VM;
//        else
//            return XDP_PASS;

        hike_pr_debug("post paolo_ip6_dst_filter");


drop:
        hike_pr_debug("DROP paolo_ip6_dst_filter");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, HIKE_MAPS_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
