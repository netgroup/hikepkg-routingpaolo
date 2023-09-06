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

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

//#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#define HIKE_PROG_NAME paolo_adv_usid

#define USID_BLOCK_LEN    4  /* 4 Bytes alias 32 bit */
#define USID_FUNC_LEN     2  /* 2 Bytes alisa 16 bit */

bpf_map(usid_params, HASH, __u32, __u32, 2);

HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
        struct in6_addr *addr;
        struct ipv6hdr *ip6h;

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*ip6h));

	if (unlikely(!ip6h))
		goto drop;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

        addr = &ip6h->daddr;

        __u32 arg_octects;
        int i;
        bool arg_zero = true;

        arg_octects = 16 - USID_BLOCK_LEN - USID_FUNC_LEN;
        for (i = 0; i < arg_octects; ++i) {
                if (addr->s6_addr[USID_BLOCK_LEN + USID_FUNC_LEN + i] != 0x00)
                        arg_zero = false;
        }

        if (arg_zero)
              goto drop;


        /* advance DA.Argument */
        memmove(&ip6h->daddr.s6_addr[USID_BLOCK_LEN], &ip6h->daddr.s6_addr[USID_BLOCK_LEN + USID_FUNC_LEN],
                arg_octects);

        memset(&addr->s6_addr[16 - USID_FUNC_LEN], 0x00, USID_FUNC_LEN);

	return HIKE_XDP_VM;

drop:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, usid_params);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
