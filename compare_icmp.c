/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Compare icmp packets from master and slave.
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/icmp.h>

#include "compare.h"
#include "compare_ipv4.h"

static void debug_print_icmp(const struct compare_info *cinfo, const void *data,
			     int length)
{
	const struct icmphdr *icmp = data;

	pr_warn("HA_compare:[ICMP] code=%u\n", icmp->code);
}

static uint32_t icmp_compare_packet(struct compare_info *m_cinfo,
				    struct compare_info *s_cinfo)
{
	return SAME_PACKET;
}

static uint32_t icmp_compare_one_packet(struct compare_info *m_cinfo,
					struct compare_info *s_cinfo)
{
	uint32_t ret = 0;

	if (m_cinfo->skb)
		ret |= BYPASS_MASTER;
	if (s_cinfo->skb)
		ret |= DROP_SLAVER;
	return ret;
}

static ipv4_compare_ops_t icmp_ops = {
	.debug_print = debug_print_icmp,
	.compare = icmp_compare_packet,
	.compare_one_packet = icmp_compare_one_packet,
};

static __init int compare_icmp_init(void)
{
	return register_ipv4_compare_ops(&icmp_ops, IPPROTO_ICMP);
}

static __exit void compare_icmp_fini(void)
{
	unregister_ipv4_compare_ops(&icmp_ops, IPPROTO_ICMP);
}

module_init(compare_icmp_init);
module_exit(compare_icmp_fini);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
