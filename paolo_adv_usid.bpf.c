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
//#include "paolo_kroute.h"

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif


#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#define USID_BLOCK_LEN 1
#define USID_FUNC_LEN  2

bpf_map(usid_params, HASH, __u32, __u32, 2);

HIKE_PROG(paolo_adv_usid)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
        struct in6_addr *addr;
        struct ipv6hdr *ip6h;
	int rc;

        hike_pr_debug("init paolo_adv_usid");

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        hike_pr_debug("pre paolo_adv_usid");

        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*ip6h));

	if (unlikely(!ip6h))
		goto drop;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;


        /* assume that DA.Argument length > 0 */

        __u32 key = USID_BLOCK_LEN;
        __u32 *value;

	__u32 blk_octects = 4;
	__u32 fnc_octects = 2;

        value = bpf_map_lookup_elem(&usid_params, &key);

        if (unlikely(!value)) {
                hike_pr_err("could not read usid_block_len from map");
		goto drop;
        }

        hike_pr_debug("paolo usid_block_len: %d", *value);
//        blk_octects = *value;


        key = USID_FUNC_LEN;
        value = bpf_map_lookup_elem(&usid_params, &key);

        if (unlikely(!value)) {
                hike_pr_err("could not read usid_func_len from map");
                goto drop;
        }

        hike_pr_debug("paolo usid_func_len: %d", *value);
//        fnc_octects = *value;

        addr = &ip6h->daddr;

	__u32 arg_octects;
	int i;
        bool arg_zero = true;

	arg_octects = 16 - blk_octects - fnc_octects;
	for (i = 0; i < arg_octects; ++i) {
		if (addr->s6_addr[blk_octects + fnc_octects + i] != 0x00)
			arg_zero = false;
	}

        if (arg_zero)
              goto drop;


	/* advance DA.Argument */
	memmove(&ip6h->daddr.s6_addr[blk_octects], &ip6h->daddr.s6_addr[blk_octects + fnc_octects],
		16 - blk_octects - fnc_octects);

	memset(&addr->s6_addr[16 - fnc_octects], 0x00, fnc_octects);


        hike_pr_debug("post paolo_adv_usid, addr");

	return HIKE_XDP_VM;

drop:
        hike_pr_debug("DROP paolo_adv_usid");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(paolo_adv_usid);
EXPORT_HIKE_PROG_MAP(paolo_adv_usid, usid_params);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
