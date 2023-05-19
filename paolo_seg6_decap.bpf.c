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

#define HIKE_PROG_NAME paolo_seg6_decap

#define hdr_ptr(ctx, off, size) \
	cur_header_pointer(ctx, NULL, off, size)

#define get_ethhdr(ctx, cur) \
	((struct ethhdr *)hdr_ptr(ctx, (cur)->mhoff, sizeof(struct ethhdr)))

#define get_ethhdr2(ctx, off) \
        ((struct ethhdr *)hdr_ptr(ctx, off, sizeof(struct ethhdr)))

#define get_ipv6hdr(ctx, cur) \
	((struct ipv6hdr *)hdr_ptr(ctx, (cur)->nhoff, sizeof(struct ipv6hdr)))

#define get_ipv4hdr(ctx, cur) \
	((struct iphdr *)hdr_ptr(ctx, (cur)->nhoff, sizeof(struct iphdr)))

#define cur_xdp_reduce_head(ctx, cur, len) \
	cur_xdp_adjust_head(ctx, cur, len)

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline void show_cur_info(const struct hdr_cursor *cur)
{
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);
}


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
        __u16 protocol;
        unsigned int maclen;
        int tot_len;
        struct ethhdr *old_eth, *eth;


        hike_pr_debug("init paolo_seg6_decap");

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        hike_pr_debug("pre paolo_seg6_decap");

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

        if (srh->segments_left > 0) {
                hike_pr_err("Segment Left is not zero");
		goto drop;
        }

        switch (srh->nexthdr) {
        case IPPROTO_IP:
                protocol = ETH_P_IP;
                break;
        case IPPROTO_IPV6:
                protocol = ETH_P_IPV6;
                break;
        case IPPROTO_ETHERNET:
        default:
                hike_pr_err("unsupported protocol <%x>", srh->nexthdr);
                goto drop;
        }

	maclen = cur->nhoff - cur->mhoff;
	if (unlikely(maclen != sizeof(struct ethhdr))) {
		hike_pr_crit("VLAN not yet supported in ethernet header");
		goto drop;
	}

        /* calculate the reduction len */
	tot_len = sizeof(struct ipv6hdr) + srh_len;

        /* retrive the actual mac header */
	old_eth = get_ethhdr2(ctx, cur->mhoff);
	if (unlikely(!old_eth)) {
		hike_pr_err("cannot access to ethernet header");
		goto drop;
	}

        /* points the cur->dataoff to the position of mac header */
        __cur_set_header_off(cur, dataoff, cur->mhoff + tot_len);

        /* points to the new position of mac header */
	eth = get_ethhdr2(ctx, cur->dataoff);
	if (unlikely(!eth))
		goto drop;

	/* copy the old mac header in the new position
         * the two headers do not overlap with each other
         */
	memcpy(eth, old_eth, sizeof(*eth));
	eth->h_proto = bpf_ntohs(protocol);

        show_cur_info(cur);
        hike_pr_debug("tot_len: %d", tot_len);
        hike_pr_debug("srh_len: %d \n", srh_len);


	/* reduce the xdp frame */
//	rc = cur_xdp_reduce_head(ctx, cur, tot_len);
	rc = bpf_xdp_adjust_head(ctx, tot_len);
	if (unlikely(rc)) {
		hike_pr_err("cannot reduce the xdp frame correctly");
		goto drop;
	}

	/* set the cur->dataoff to the beginning of the frame */
	__pull(cur, 0 - tot_len);

        /* set the cur->mhoff to the beginning of the frame */
	cur_reset_mac_header(cur);

        /* set the cur->nhoff after the mac header */
        __cur_set_header_off(cur, nhoff, cur->mhoff + maclen);

        /* points the cur->dataoff to the network header offset*/
        __cur_set_header_off(cur, dataoff, cur->nhoff);

        /* unset the trasport header offset (not used in L3 context) */
        cur_transport_header_unset(cur);

        show_cur_info(cur);

        hike_pr_debug("post paolo_seg6_decap, OK");

	return HIKE_XDP_VM;

drop:
        hike_pr_debug("DROP paolo_seg6_decap");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
