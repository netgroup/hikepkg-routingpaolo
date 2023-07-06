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

HIKE_PROG(paolo_kroute)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	int rc;

        hike_pr_debug("hike init paolo_kroute");

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

        hike_pr_debug("hike pre paolo_kroute");

	/* lookup with FIB rules */
	rc = __paolo_route(ctx, cur, 0);

        hike_pr_debug("hike post paolo_kroute; rc: %d", rc);

	return rc;

drop:
        hike_pr_debug("hike DROP paolo_kroute");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(paolo_kroute);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
