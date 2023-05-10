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

#define HIKE_PROG_NAME paolo_seg6_end

HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
        struct in6_addr *daddr;
        struct ipv6hdr *ip6h;
	struct ipv6_sr_hdr *srh;
        int srh_minlen = -EINVAL;
	int srh_len = -EINVAL;
	int srhoff = -EINVAL;
	int rc;

        hike_pr_debug("init paolo_seg6_end");

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        hike_pr_debug("pre paolo_seg6_end");

        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*ip6h));

	if (unlikely(!ip6h))
		goto drop;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

        /* find the SRH header and try to access it */
        srhoff = cur->nhoff;
	rc = ipv6_find_hdr(ctx, cur, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot locate SRH");
		goto drop;
	}

	/* we are looking for an SRH with at least one sid. The first sid in
	 * the sidlist is the last one ;-)
	 */
	srh_minlen = sizeof(*srh) + sizeof(srh->segments[0]);
	srh = (struct ipv6_sr_hdr *)cur_header_pointer(ctx, cur, srhoff,
						       srh_minlen);
	if (unlikely(!srh)) {
		hike_pr_err("SRH must contain one SID at least");
		goto drop;
	}

	srh_len = (srh->hdrlen + 1) << 3;
	if (unlikely(srh_minlen > srh_len)) {
		hike_pr_err("invalid SRH length");
		goto drop;
	}

        if (srh->segments_left == 0) {
                hike_pr_err("Segment Left is zero");
		goto drop;
        }

        /* perfom the END behavior action on the packet */
	srh->segments_left--;
	daddr = &srh->segments + srh->segments_left;

/*        if (unlikely(!daddr))
                goto drop;
*/
        ip6h->daddr = *daddr;

        hike_pr_debug("post paolo_seg6_end, OK");

	return HIKE_XDP_VM;

drop:
        hike_pr_debug("DROP paolo_seg6_end");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
