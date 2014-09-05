/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Compare arp packets from master and slave.
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "compare.h"

bool ignore_arp_packet = 1;
module_param(ignore_arp_packet, bool, 0644);
MODULE_PARM_DESC(ignore_arp_packet, "ignore arp packet");

struct arp_reply {
	unsigned char		ar_sha[ETH_ALEN];
	unsigned char		ar_sip[4];
	unsigned char		ar_tha[ETH_ALEN];
	unsigned char		ar_tip[4];
};

struct arp_compare_info {
	struct net_device *dev;
	uint32_t skb_iif;
	uint32_t reserved[29];
};

#define ARP_CMP_INFO(compare_info) ((struct arp_compare_info *)compare_info->private_data)

static void print_arp_packet(const struct arphdr *arp)
{
	struct arp_reply *temp;

	pr_warn("HA_compare:[ARP] ar_hrd=%u, ar_pro=%u\n",
		ntohs(arp->ar_hrd), ntohs(arp->ar_pro));
	pr_warn("HA_compare:[ARP] ar_hln=%u, ar_pln=%u, ar_op=%u\n",
		arp->ar_hln, arp->ar_pln, ntohs(arp->ar_op));
	if (ntohs(arp->ar_op) == ARPOP_REPLY || ntohs(arp->ar_op) == ARPOP_REQUEST) {
		temp = (struct arp_reply *)((char*)arp + sizeof(struct arphdr));
		pr_warn("HA_compare:[ARP] ar_sha: %pM, ar_sip: %pI4\n", temp->ar_sha, temp->ar_sip);
		pr_warn("HA_compare:[ARP] ar_tha: %pM, ar_tip: %pI4\n", temp->ar_tha, temp->ar_tip);
	}
}

static void
print_arp_info(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	pr_warn("HA_compare: master packet, len=%d\n",
		m_cinfo->length);
	print_arp_packet(m_cinfo->arp);
	pr_warn("HA_compare: slave packet, len=%d\n",
		s_cinfo->length);
	print_arp_packet(s_cinfo->arp);
}

static void update_arp_compare_info(struct arp_compare_info *arp_cinfo,
				    struct sk_buff *skb)
{
	arp_cinfo->dev = skb->dev;
	arp_cinfo->skb_iif = skb->skb_iif;
}

static uint32_t
compare_arp_packet(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	uint32_t ret = BYPASS_MASTER;

	if (s_cinfo->arp->ar_op != ARPOP_REQUEST)
		ret |= DROP_SLAVER;

	return ret;
}

static uint32_t
__arp_compare_packet(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	update_arp_compare_info(ARP_CMP_INFO(m_cinfo), m_cinfo->skb);

	if (ignore_arp_packet)
		return compare_arp_packet(m_cinfo, s_cinfo);

	if (m_cinfo->length != s_cinfo->length)
		return CHECKPOINT;

	return default_compare_data(m_cinfo->packet, s_cinfo->packet,
				    m_cinfo->length);
}

static uint32_t
arp_compare_packet(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	uint32_t ret = __arp_compare_packet(m_cinfo, s_cinfo);

	if (ret & CHECKPOINT)
		print_arp_info(m_cinfo, s_cinfo);

	return ret;
}

static struct sk_buff *create_new_skb(struct sk_buff *skb,
				      struct compare_info *cinfo)
{
	struct sk_buff *new_skb;

	new_skb = skb_copy(skb, GFP_ATOMIC);
	if (!new_skb)
		return NULL;

	new_skb->dev = ARP_CMP_INFO(cinfo)->dev;
	new_skb->skb_iif = ARP_CMP_INFO(cinfo)->skb_iif;
	cinfo->skb = new_skb;

	return new_skb;
}

static uint32_t
arp_compare_one_packet(struct compare_info *m_cinfo,
		       struct compare_info *s_cinfo)
{
	if (!ARP_CMP_INFO(m_cinfo)->dev || !ignore_arp_packet)
		return 0;

	if (m_cinfo->skb) {
		update_arp_compare_info(ARP_CMP_INFO(m_cinfo), m_cinfo->skb);
		return BYPASS_MASTER;
	}

	if (unlikely(!s_cinfo->skb))
		return 0;

	if (s_cinfo->arp->ar_op != ARPOP_REQUEST)
		return DROP_SLAVER;

	if (create_new_skb(s_cinfo->skb, m_cinfo) == NULL)
		return 0;

	return BYPASS_MASTER | DROP_SLAVER;
}

compare_net_ops_t arp_ops = {
	.compare_packets = arp_compare_packet,
	.compare_one_packet = arp_compare_one_packet,
};

static int __init compare_arp_init(void)
{
	return register_net_compare_ops(&arp_ops, COMPARE_ARP);
}

static void __exit compare_arp_fini(void)
{
	unregister_net_compare_ops(&arp_ops, COMPARE_ARP);
}

module_init(compare_arp_init);
module_exit(compare_arp_fini);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
