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
#include "seg6_end.h"

//#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

HIKE_PROG(paolo_seg6_end2)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	int rc;

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

	/* performs the end behavior */
	rc = __paolo_seg6_end(ctx, cur);

	return rc;

drop:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(paolo_seg6_end2);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
