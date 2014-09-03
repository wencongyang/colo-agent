/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Compare packets from master and slave.
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
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <net/pkt_sched.h>
#include <asm/ioctl.h>
#include <linux/kthread.h>

#include "comm.h"
#include "compare.h"
#include "compare_device.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

uint32_t state = state_comparing;

const compare_net_ops_t *compare_net_ops[COMPARE_LAST];
DEFINE_MUTEX(net_ops_lock);

/* compare_xxx_packet() returns:
 *   0: do a new checkpoint
 *   1: bypass the packet from master,
 *   2: drop the packet from slave
 *   3: bypass the packet from master, and drop the packet from slave
 */

uint32_t default_compare_data(void *m_data, void *s_data, int length)
{
	int ret = memcmp(m_data, s_data, length);

	return ret ? CHECKPOINT | UPDATE_COMPARE_INFO : SAME_PACKET;
}
EXPORT_SYMBOL(default_compare_data);

int register_net_compare_ops(const compare_net_ops_t *ops,
			     unsigned char protocol)
{
	if (protocol >= COMPARE_LAST)
		return -EINVAL;

	mutex_lock(&net_ops_lock);
	if (compare_net_ops[protocol]) {
		mutex_unlock(&net_ops_lock);
		return -EBUSY;
	}

	rcu_assign_pointer(compare_net_ops[protocol], ops);
	mutex_unlock(&net_ops_lock);

	synchronize_rcu();
	return 0;
}

int unregister_net_compare_ops(const compare_net_ops_t *ops,
			       unsigned char protocol)
{
	if (protocol >= COMPARE_LAST)
		return -EINVAL;

	mutex_lock(&net_ops_lock);
	if (compare_net_ops[protocol] != ops) {
		mutex_unlock(&net_ops_lock);
		return -EINVAL;
	}

	rcu_assign_pointer(compare_net_ops[protocol], NULL);
	mutex_unlock(&net_ops_lock);

	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL(register_net_compare_ops);
EXPORT_SYMBOL(unregister_net_compare_ops);

const compare_net_ops_t *get_compare_net_ops(unsigned short protocol)
{
	unsigned char compare_protocol;

	switch(ntohs(protocol)) {
	case ETH_P_IP:
		compare_protocol = COMPARE_IPV4;
		break;
	case ETH_P_IPV6:
		compare_protocol = COMPARE_IPV6;
		break;
	case ETH_P_ARP:
		compare_protocol = COMPARE_ARP;
		break;
	default:
		return NULL;
	}

	return rcu_dereference(compare_net_ops[compare_protocol]);
}

static uint32_t
default_compare_packets(struct compare_info *m_cinfo,
			struct compare_info *s_cinfo)
{
	uint32_t ret;

	if (m_cinfo->length != s_cinfo->length) {
		pr_warn("HA_compare: the length of packet is different\n");
		pr_warn("  protocol: %04x\n", ntohs(m_cinfo->eth->h_proto));
		return CHECKPOINT;
	}

	ret = default_compare_data(m_cinfo->packet, s_cinfo->packet,
				   m_cinfo->length);
	if (ret & CHECKPOINT) {
		pr_warn("HA_compare: the data is different\n");
		pr_warn("  protocol: %04x\n", ntohs(m_cinfo->eth->h_proto));
	}

	return ret;
}

static uint32_t
compare_skb(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	uint32_t ret = CHECKPOINT;
	const compare_net_ops_t *ops;

	m_cinfo->eth = (struct ethhdr *)m_cinfo->skb->data;
	s_cinfo->eth = (struct ethhdr *)s_cinfo->skb->data;
	m_cinfo->length = m_cinfo->skb->len;
	s_cinfo->length = s_cinfo->skb->len;

	if (unlikely(m_cinfo->length < sizeof(struct ethhdr))) {
		pr_warn("HA_compare: master packet is corrupted\n");
		goto different;
	}

	if (unlikely(s_cinfo->length < sizeof(struct ethhdr))) {
		pr_warn("HA_compare: slave packet is corrupted\n");
		goto different;
	}

	if (m_cinfo->length < 60 && s_cinfo->length == 60)
		s_cinfo->length = m_cinfo->length;

	if (unlikely(m_cinfo->eth->h_proto != s_cinfo->eth->h_proto)) {
		pr_warn("HA_compare: protocol in eth header is different\n");
		pr_warn("HA_compare: master's protocol: %d\n",
			ntohs(m_cinfo->eth->h_proto));
		pr_warn("HA_compare: slave's protocol: %d\n",
			ntohs(s_cinfo->eth->h_proto));
		goto different;
	}

	m_cinfo->packet = (char *)m_cinfo->eth + sizeof(struct ethhdr);
	s_cinfo->packet = (char *)s_cinfo->eth + sizeof(struct ethhdr);
	m_cinfo->length -= sizeof(struct ethhdr);
	s_cinfo->length -= sizeof(struct ethhdr);

	rcu_read_lock();
	ops = get_compare_net_ops(m_cinfo->eth->h_proto);
	if (ops && ops->compare_packets)
		ret = ops->compare_packets(m_cinfo, s_cinfo);
	else
		ret = default_compare_packets(m_cinfo, s_cinfo);
	rcu_read_unlock();

	if (ret & CHECKPOINT)
		pr_warn("HA_compare: compare_xxx_packet() fails %04x\n",
			ntohs(m_cinfo->eth->h_proto));

different:
	return ret;
}

static void release_skb(struct sk_buff_head *head, struct sk_buff *skb)
{
	struct sk_buff *next;

	if (!(FRAG_CB(skb)->flags & IS_FRAGMENT)) {
		skb_queue_tail(head, skb);
		return;
	}

	next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = NULL;
	do {
		skb_queue_tail(head, skb);
		skb = next;
		if (next)
			next = next->next;
	} while (skb != NULL);
}

static uint32_t compare_one_skb(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	struct sk_buff *skb;
	struct compare_info *cinfo = NULL;
	struct compare_info *other_cinfo = NULL;
	uint32_t ret = 0;
	const compare_net_ops_t *ops;

	if (m_cinfo->skb) {
		cinfo = m_cinfo;
		other_cinfo = s_cinfo;
		ret = BYPASS_MASTER;
	} else if (s_cinfo->skb) {
		cinfo = s_cinfo;
		other_cinfo = m_cinfo;
		ret = DROP_SLAVER;
	} else
		BUG();

	skb = cinfo->skb;

	cinfo->eth = (struct ethhdr *)cinfo->skb->data;
	cinfo->length = cinfo->skb->len;

	if (unlikely(cinfo->length < sizeof(struct ethhdr))) {
		pr_warn("HA_compare: %s packet is corrupted\n",
			m_cinfo->skb ? "master" : "slave");
		goto err;
	}

	cinfo->packet = (char *)cinfo->eth + sizeof(struct ethhdr);
	cinfo->length -= sizeof(struct ethhdr);

	/* clear other_info to avoid unexpected error */
	other_cinfo->eth = NULL;
	other_cinfo->packet = NULL;
	other_cinfo->length = 0;

	rcu_read_lock();
	ops = get_compare_net_ops(cinfo->eth->h_proto);
	if (ops && ops->compare_one_packet)
		ret = ops->compare_one_packet(m_cinfo, s_cinfo);
	else
		/* unsupported */
		ret = 0;
	rcu_read_unlock();

err:
	return ret;
}

static void compare_one_connection(struct connect_info *conn_info)
{
	struct sk_buff *skb_m;
	struct sk_buff *skb_s;
	int ret;
	struct compare_info info_m, info_s;
	struct if_connections *ics = conn_info->ics;
	bool skip_compare_one = false;

	while (1) {
		if (state != state_comparing)
			break;

		skb_m = skb_dequeue(&conn_info->master_queue);
		skb_s = skb_dequeue(&conn_info->slave_queue);

		if (!skb_m && !skb_s)
			break;

		if ((!skb_m || !skb_s) && skip_compare_one) {
			/* We have checked skb_m or skb_s */
			if (skb_m)
				skb_queue_head(&conn_info->master_queue, skb_m);

			if (skb_s)
				skb_queue_head(&conn_info->slave_queue, skb_s);
			break;
		}

		info_m.skb = skb_m;
		info_s.skb = skb_s;
		info_m.private_data = &conn_info->m_info;
		info_s.private_data = &conn_info->s_info;
		if (!skb_m || !skb_s)
			ret = compare_one_skb(&info_m, &info_s);
		else
			ret = compare_skb(&info_m, &info_s);
		if (!(ret & CHECKPOINT)) {
			if (!skb_m && info_m.skb)
				skb_m = info_m.skb;

			if (likely(ret & BYPASS_MASTER)) {
				release_skb(&ics->master_data->rel, skb_m);
				netif_schedule_queue(ics->master_data->sch->dev_queue);
			} else if (skb_m) {
				skb_queue_head(&conn_info->master_queue, skb_m);
			}

			if (!skb_s && info_s.skb)
				skb_s = info_s.skb;

			if (likely(ret & DROP_SLAVER)) {
				release_skb(&ics->slave_data->rel, skb_s);
				netif_schedule_queue(ics->slave_data->sch->dev_queue);
			} else if (skb_s) {
				skb_queue_head(&conn_info->slave_queue, skb_s);
			}
			//pr_info("netif_schedule%u.\n", cnt);
			if (!ret)
				skip_compare_one = true;
			else
				skip_compare_one = false;
		} else {
			/*
			 *  Put makster's skb to temporary queue, drop slave's.
			 */
			if (skb_m)
				release_skb(&ics->wait_for_release, skb_m);
			if (skb_s)
				release_skb(&ics->slave_data->rel, skb_s);

			state = state_incheckpoint;
			wake_up_interruptible(&ics->vmcs->checkpoint_queue);
			break;
		}
	}
}

static struct connect_info *get_connect_info(struct vm_connections *vmcs)
{
	struct connect_info *conn_info = NULL;

	spin_lock_bh(&vmcs->compare_lock);
	if (list_empty(&vmcs->compare_head))
		goto out;

	conn_info = list_first_entry(&vmcs->compare_head, struct connect_info,
				 compare_list);
	list_del_init(&conn_info->compare_list);
	conn_info->state = IN_COMPARE;
out:
	spin_unlock_bh(&vmcs->compare_lock);
	return conn_info;
}

int compare_kthread(void *data)
{
	struct connect_info *conn_info;
	int wakeup;
	struct vm_connections *vmcs = data;

	while(!kthread_should_stop()) {
		wait_event_interruptible(vmcs->compare_queue,
					 !list_empty(&vmcs->compare_head) ||
					 kthread_should_stop());

		if (kthread_should_stop())
			break;

		while(!list_empty(&vmcs->compare_head)) {
			conn_info = get_connect_info(vmcs);
			if (conn_info) {
				compare_one_connection(conn_info);
				spin_lock_bh(&vmcs->compare_lock);
				wakeup = conn_info->state & IN_DESTROY;
				conn_info->state = 0;
				spin_unlock_bh(&vmcs->compare_lock);
				if (unlikely(wakeup))
					wake_up_interruptible(&conn_info->wait);
			}

			if (kthread_should_stop())
				break;
		}
	}

	return 0;
}
