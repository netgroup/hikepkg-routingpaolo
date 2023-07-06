#ifndef _SEG6_END_H
#define _SEG6_END_H

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/errno.h>

#include "hdr_cursor.h"

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "hike_vm.h"
#include "parse_helpers.h"

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

static __always_inline int
__seg6_end(struct xdp_md *ctx, struct hdr_cursor *cur)
{
        int srh_minlen = -EINVAL;
        struct ipv6_sr_hdr *srh;
        struct in6_addr *daddr;
        int srh_len = -EINVAL;
        int srhoff = -EINVAL;
        struct ipv6hdr *ip6h;
        int rc;

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

        ip6h->daddr = *daddr;

        hike_pr_debug("post paolo_seg6_end, OK");

        return HIKE_XDP_VM;

drop:
        hike_pr_debug("DROP paolo_seg6_end");
        return XDP_ABORTED;
}
