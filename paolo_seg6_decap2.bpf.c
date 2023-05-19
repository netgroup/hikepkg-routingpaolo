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

#define HIKE_PROG_NAME paolo_seg6_decap2

#define hdr_ptr(ctx, off, size) \
	cur_header_pointer(ctx, NULL, off, size)

#define get_ethhdr(ctx, off) \
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

#define NEXTHDR_ETHERNET 143

static __always_inline void show_cur_info(const struct hdr_cursor *cur)
{
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);
}

static __always_inline int handle_srh(struct xdp_md *ctx, struct hdr_cursor *cur,
                                      struct ipv6_sr_hdr *srh, int srhoff,
                                      int *srh_len, __u8 *nexthdr)
{
        int srh_minlen = -EINVAL;

        /* we are looking for an SRH with at least one sid.
	* The first sid in the sidlist is the last one ;-)
	*/
        srh_minlen = sizeof(*srh) + sizeof(srh->segments[0]);
	srh = (struct ipv6_sr_hdr *)cur_header_pointer(ctx, cur, srhoff,
						       srh_minlen);
	if (unlikely(!srh)) {
	        hike_pr_err("SRH must contain one SID at least");
	        return -EINVAL;
	}

        hike_pr_debug("(srh->hdrlen + 1 << 3): %d \n", ((srh->hdrlen + 1) << 3));

	*srh_len = (srh->hdrlen + 1) << 3;
	if (unlikely(srh_minlen > *srh_len)) {
	        hike_pr_err("invalid SRH length");
	        return -EINVAL;
        }

        if (srh->segments_left > 0) {
                hike_pr_err("Segment Left is not zero");
	        return -EINVAL;
        }

        hike_pr_debug("srh_len: %d \n", *srh_len);
        *nexthdr = srh->nexthdr;

        return 0;
}

static __always_inline int adjust_mac_header(struct xdp_md *ctx, struct hdr_cursor *cur,
                                              int delta, __u16 protocol)
{
        struct ethhdr *old_eth, *eth;
        unsigned int maclen;

	maclen = cur->nhoff - cur->mhoff;
	if (unlikely(maclen != sizeof(struct ethhdr))) {
		hike_pr_crit("VLAN not yet supported in ethernet header");
	        return -EINVAL;
	}

        /* retrive the actual mac header */
	old_eth = get_ethhdr(ctx, cur->mhoff);
	if (unlikely(!old_eth)) {
		hike_pr_err("cannot access to ethernet header");
	        return -EINVAL;
	}

        /* points the cur->dataoff to the new position of mac header */
        __cur_set_header_off(cur, dataoff, cur->mhoff + delta);

        /* points to the new position of mac header */
	eth = get_ethhdr(ctx, cur->dataoff);
	if (unlikely(!eth))
	        return -EINVAL;

	/* copy the old mac header in the new position
         * the two headers do not overlap with each other
         */
	memcpy(eth, old_eth, sizeof(*eth));
	eth->h_proto = bpf_ntohs(protocol);

        /* points the cur->mhoff to the new position of mac header */
        __cur_set_header_off(cur, mhoff, cur->dataoff);

        return 0;
}

static __always_inline __u16 nxthdr_to_ethproto(__u8 nexthdr)
{
        switch(nexthdr) {
        case NEXTHDR_IPV4:
                return ETH_P_IP;
        case NEXTHDR_IPV6:
                return ETH_P_IPV6;
        case NEXTHDR_ETHERNET:
                return NEXTHDR_ETHERNET;
        default:
                hike_pr_err("unsupported protocol <%x>", nexthdr);
	        return -EINVAL;
        }
}


HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct ipv6_sr_hdr *srh;
	struct hdr_cursor *cur;
//        struct in6_addr *daddr;
	int srh_len = -EINVAL;
//	int srhoff = -EINVAL;
        struct ipv6hdr *ip6h;
        int offset = 0;
        __u16 protocol;
        __u8 nexthdr;
        int deltaoff;
	int rc;


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

        hike_pr_debug("#### cursor pre find next header ####");
        show_cur_info(cur);

        /* add to delta offset the IPv6 header size */
	deltaoff = sizeof(struct ipv6hdr);

        /* find the SRH header if exist of the inner headers */
	rc = ipv6_find_hdr(ctx, cur, &offset, ip6h->nexthdr, NULL, NULL);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot locate SRH/Inner Headers");
		goto drop;
	}

        hike_pr_debug("ipv6_find_hdr: protocol <%d>, offset: %d", ip6h->nexthdr, offset);

        nexthdr = ip6h->nexthdr;

        if (nexthdr == NEXTHDR_ROUTING) {
                hike_pr_debug("#### enter in SRH path ####");

                /* Validate the SRH and check if the Segment Left is zero.
                 * Compute the header offset and retrive the nexthdr id.
                 * Its assumes the next header is the inner packet.
                 */
                rc = handle_srh(ctx, cur, srh, offset, &srh_len, &nexthdr);
        	if (unlikely(rc < 0)) {
	        	hike_pr_err("cannot handle SRH Header");
		        goto drop;
		}

                /* convert the ipproto id to ethernet ethertype */
                protocol = nxthdr_to_ethproto(nexthdr);
		if (unlikely(protocol < 0)) {
			goto drop;
		}

                /* add to delta offeset the SRH lenght */
                deltaoff += srh_len;
        }

        if (nexthdr == NEXTHDR_IPV4) {
                hike_pr_debug("#### enter in IPv4 path ####");
                /* convert the ipproto id to ethernet ethertype */
                protocol = nxthdr_to_ethproto(nexthdr);
		if (unlikely(protocol < 0)) {
			goto drop;
		}

                /* move the mac header to before the inner header */
                rc = adjust_mac_header(ctx, cur, deltaoff, protocol);
        	if (unlikely(rc < 0)) {
	        	hike_pr_err("cannot handle SRH Header");
		        goto drop;
		}

                /* points the cur->nhoff to the inner header */
                __cur_set_header_off(cur, nhoff, cur->nhoff + deltaoff);

                /* unset the trasport header offset (not used in L3 context) */
                cur_transport_header_unset(cur);
        } else if (nexthdr == NEXTHDR_IPV6) {
                hike_pr_debug("#### enter in IPv6 path ####");
                /* convert the ipproto id to ethernet ethertype */
                protocol = nxthdr_to_ethproto(nexthdr);
		if (unlikely(protocol < 0)) {
			goto drop;
		}

                /* move the mac header to before the inner header */
                rc = adjust_mac_header(ctx, cur, deltaoff, protocol);
        	if (unlikely(rc < 0)) {
	        	hike_pr_err("cannot handle SRH Header");
		        goto drop;
		}

                /* points the cur->nhoff to the inner header */
                __cur_set_header_off(cur, nhoff, cur->nhoff + deltaoff);

                /* unset the trasport header offset (not used in L3 context) */
                cur_transport_header_unset(cur);
        } else if (nexthdr == NEXTHDR_ETHERNET) {
                hike_pr_debug("#### enter in ETHERNET path ####");
                /* points the cur->mhoff to the start of inner header */
                __cur_set_header_off(cur, mhoff, cur->nhoff + deltaoff);

                /* points the cur->nhoff after the mac header */
                __cur_set_header_off(cur, nhoff, cur->mhoff + sizeof(struct ethhdr));

                /* unset the trasport header offset (not used in L3 context) */
                cur_transport_header_unset(cur);
        } else {
                hike_pr_err("invalid inner packet <%x>", nexthdr);
                goto drop;
        }


        hike_pr_debug("#### cursor post find next header ####");
        show_cur_info(cur);
        hike_pr_debug("deltaoff: %d", deltaoff);
        hike_pr_debug("srh_len: %d", srh_len);


	/* reduce the xdp frame */
	rc = cur_xdp_reduce_head(ctx, cur, deltaoff);
//	rc = bpf_xdp_adjust_head(ctx, tot_len);
	if (unlikely(rc)) {
		hike_pr_err("cannot reduce the xdp frame correctly");
		goto drop;
	}

        hike_pr_debug("#### cursor post xdp reduce ####");
        show_cur_info(cur);

	/* set the cur->dataoff to the beginning of the frame */
	//__pull(cur, 0 - dataoff);

        /* set the cur->mhoff to the beginning of the frame */
	//cur_reset_mac_header(cur);

        /* set the cur->nhoff after the mac header */
        //__cur_set_header_off(cur, nhoff, cur->mhoff + maclen);

        /* points the cur->dataoff to the network header offset*/
        __cur_set_header_off(cur, dataoff, cur->nhoff);

        /* unset the trasport header offset (not used in L3 context) */
        //cur_transport_header_unset(cur);

        hike_pr_debug("#### cursor final pre exit ####");
        show_cur_info(cur);

        hike_pr_debug("post paolo_seg6_decap, OK");

	return HIKE_XDP_VM;

drop:
        hike_pr_debug("DROP paolo_seg6_decap");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
