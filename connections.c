/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Manage the connections
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
#include <linux/ip.h>
#include <net/ip.h>

#include "connections.h"
#include "comm.h"
#include "ipv4_fragment.h"

static struct list_head vm_list = LIST_HEAD_INIT(vm_list);
static spinlock_t vm_lock;

static void init_if_connections(struct if_connections *ics)
{
	int i;

	memset(ics, 0, sizeof(*ics));
	for (i = 0; i < HASH_NR; i++)
		INIT_LIST_HEAD(&ics->entry[i]);

	INIT_LIST_HEAD(&ics->list);
	skb_queue_head_init(&ics->wait_for_release);
}

/* copied from kernel, old kernel doesn't have the API skb_flow_dissect() */

/* copy saddr & daddr, possibly using 64bit load/store
 * Equivalent to :	flow->src = iph->saddr;
 *			flow->dst = iph->daddr;
 */
static void iph_to_flow_copy_addrs(struct connection_keys *flow,
				   const struct iphdr *iph)
{
	BUILD_BUG_ON(offsetof(typeof(*flow), dst) !=
		     offsetof(typeof(*flow), src) + sizeof(flow->src));
	memcpy(&flow->src, &iph->saddr, sizeof(flow->src) + sizeof(flow->dst));
}

#define ip_is_fragment(iph)	(iph->frag_off & htons(IP_MF | IP_OFFSET))

static inline int __proto_ports_offset(int proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:	/* SPI */
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return 0;
	case IPPROTO_AH:	/* SPI */
		return 4;
	default:
		return -EINVAL;
	}
}

/*
 * return value:
 *   -1: error
 *    0: normal
 *    1: ip fragment
 */
static int __skb_flow_dissect(const struct sk_buff *skb,
			      struct connection_keys *flow,
			      bool check_fragment)
{
	int poff, nhoff = skb_network_offset(skb);
	u8 ip_proto;
	__be16 proto = skb->protocol;

	memset(flow, 0, sizeof(*flow));

	switch (proto) {
	case __constant_htons(ETH_P_IP): {
		const struct iphdr *iph;
		struct iphdr _iph;

		iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
		if (!iph)
			return -1;

		if (check_fragment && ip_is_fragment(iph))
			return 1;
		else if (iph->protocol != 0)
			ip_proto = iph->protocol;
		else
			return -1;
		iph_to_flow_copy_addrs(flow, iph);
		nhoff += iph->ihl * 4;
		break;
	}
	default:
		return 0;
	}

	flow->ip_proto = ip_proto;
	poff = __proto_ports_offset(ip_proto);
	if (poff >= 0) {
		__be32 *ports, _ports;

		nhoff += poff;
		/* poff is 0 or 4, so the port is stored in fragment 0 */
		ports = skb_header_pointer(skb, nhoff, sizeof(_ports), &_ports);
		if (ports)
			flow->ports = *ports;
		else
			return -1;
	}

	flow->thoff = (u16) nhoff;

	return 0;
}

static struct connect_info *alloc_connect_info(struct connection_keys *key)
{
	struct connect_info *conn_info;

	conn_info = kzalloc(sizeof(*conn_info), GFP_ATOMIC);
	if (!conn_info)
		return NULL;

	conn_info->key = *key;
	INIT_LIST_HEAD(&conn_info->list);
	INIT_LIST_HEAD(&conn_info->compare_list);
	skb_queue_head_init(&conn_info->master_queue);
	skb_queue_head_init(&conn_info->slave_queue);
	conn_info->state = 0;
	init_waitqueue_head(&conn_info->wait);
	conn_info->ics = NULL;
	conn_info->flushed = 0;

	return conn_info;
}

static struct connect_info *get_connect_info(struct list_head *head,
					     struct connection_keys *key)
{
	struct connect_info *conn_info;

	list_for_each_entry(conn_info, head, list) {
		if (conn_info->key.src == key->src &&
		    conn_info->key.dst == key->dst &&
		    conn_info->key.ports == key->ports &&
		    conn_info->key.ip_proto == key->ip_proto)
			return conn_info;
	}

	return NULL;
}

static void free_fragments(struct sk_buff *head, struct sk_buff *except)
{
	struct sk_buff *skb = head;
	struct sk_buff *next;

	do {
		if (skb == head)
			next = skb_shinfo(skb)->frag_list;
		else
			next = skb->next;

		if (skb != except )
			kfree_skb(skb);
		else if (skb == head)
			skb_shinfo(skb)->frag_list = NULL;
		else
			skb->next = NULL;

		skb = next;
	} while (skb != NULL);
}

struct connect_info *insert(struct if_connections *ics, struct sk_buff *skb,
			    uint32_t flags)
{
	struct connection_keys key;
	struct connect_info *conn_info;
	struct sk_buff *head = NULL;
	uint32_t hash;
	int i;
	int ret;

	FRAG_CB(skb)->flags = 0;
	ret = __skb_flow_dissect(skb, &key, true);
	if (ret < 0)
		return NULL;
	else if (ret > 0) {
		struct ip_frags *ip_frags;

		if (flags & IS_MASTER)
			ip_frags = &ics->master_data->ipv4_frags;
		else
			ip_frags = &ics->slave_data->ipv4_frags;
		head = ipv4_defrag(skb, ip_frags);
		if (IS_ERR(head)) {
			if (PTR_ERR(head) != -EINPROGRESS)
				return NULL;

			return ERR_PTR(-EINPROGRESS);
		}

		ret = __skb_flow_dissect(head, &key, false);
		if (ret < 0) {
			free_fragments(head, skb);
			return NULL;
		}
		FRAG_CB(head)->flags |= IS_FRAGMENT;
	}

	hash = jhash(&key, sizeof(key), JHASH_INITVAL);

	i = hash % HASH_NR;
	conn_info = get_connect_info(&ics->entry[i], &key);
	if (unlikely(!conn_info)) {
		conn_info = alloc_connect_info(&key);
		if (unlikely(!conn_info)) {
			if (head)
				free_fragments(head, skb);
			return NULL;
		}

		conn_info->ics = ics;
		list_add_tail(&conn_info->list, &ics->entry[i]);
	}

	conn_info->touch_time = jiffies_64;
	if (flags & IS_MASTER)
		skb_queue_tail(&conn_info->master_queue, head ? head : skb);
	else
		skb_queue_tail(&conn_info->slave_queue, head ? head : skb);

	if (flags & IS_MASTER)
		conn_info->flushed = 0;

	return conn_info;
}

static void destroy_connection_info(struct connect_info *conn_info, uint32_t flags)
{
	struct sk_buff_head *head;
	struct sk_buff *skb;

	if (flags & IS_MASTER)
		head = &conn_info->master_queue;
	else
		head = &conn_info->slave_queue;

	while ((skb = skb_dequeue(head)) != NULL) {
		if (FRAG_CB(skb)->flags & IS_FRAGMENT)
			free_fragments(skb, NULL);
		else
			kfree_skb(skb);
	}
}

static void wait_for_comparing_finished(struct connect_info *conn_info)
{
	struct vm_connections *vmcs = conn_info->ics->vmcs;

	spin_lock_bh(&vmcs->compare_lock);
	if (list_empty(&conn_info->list) && conn_info->state & IN_COMPARE)
		goto wait;
	if (!list_empty(&conn_info->list))
		list_del_init(&conn_info->list);
	spin_unlock_bh(&vmcs->compare_lock);

	return;

wait:
	conn_info->state |= IN_DESTROY;
	spin_unlock_bh(&vmcs->compare_lock);
	wait_event_interruptible(conn_info->wait, !(conn_info->state & IN_COMPARE));
}

/*
 * don't call it to destroy both master and slave interface connections
 * at the same time
 */
static void destroy_connections(struct if_connections *ics, uint32_t flags)
{
	int i;
	struct connect_info *conn_info, *temp;
	struct vm_connections *vmcs = ics->vmcs;

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry_safe(conn_info, temp, &ics->entry[i], list) {
wait:
			wait_for_comparing_finished(conn_info);
			spin_lock_bh(&vmcs->compare_lock);
			if (list_empty(&conn_info->compare_list) &&
			    conn_info->state & IN_COMPARE) {
				spin_unlock_bh(&vmcs->compare_lock);
				goto wait;
			}
			if (!list_empty(&conn_info->list))
				list_del_init(&conn_info->list);
			destroy_connection_info(conn_info, flags);
			spin_unlock_bh(&vmcs->compare_lock);
			if (flags & DESTROY)
				kfree(conn_info);
		}
	}
}

static struct vm_connections *alloc_vm_connections(int vm_idx)
{
	struct vm_connections *vmcs;

	spin_lock(&vm_lock);
	list_for_each_entry(vmcs, &vm_list, vm_entry) {
		if (vmcs->vm_idx == vm_idx)
			goto found;
	}

	vmcs = kmalloc(sizeof(struct vm_connections), GFP_ATOMIC);
	if (!vmcs) {
		vmcs = ERR_PTR(-ENOMEM);
		goto found;
	}

	INIT_LIST_HEAD(&vmcs->vm_ics);
	vmcs->vm_idx = vm_idx;
	spin_lock_init(&vmcs->lock);
	list_add_tail(&vmcs->vm_entry, &vm_list);
	vmcs->compare_data = NULL;
	spin_lock_init(&vmcs->compare_lock);
	INIT_LIST_HEAD(&vmcs->compare_head);
	init_waitqueue_head(&vmcs->compare_queue);
	init_waitqueue_head(&vmcs->checkpoint_queue);
	kref_init(&vmcs->ref);

found:
	spin_unlock(&vm_lock);

	return vmcs;
}

struct if_connections *
alloc_if_connections(struct colo_idx *idx, int flags, int vm_idx)
{
	struct if_connections *ics;
	struct vm_connections *vmcs;

	vmcs = alloc_vm_connections(vm_idx);
	if (IS_ERR_OR_NULL(vmcs))
		return (void *)vmcs;

	spin_lock(&vmcs->lock);
	list_for_each_entry(ics, &vmcs->vm_ics, list) {
		if (ics->idx.master_idx != idx->master_idx ||
		    ics->idx.slave_idx != idx->slave_idx)
			continue;

		if (flags & IS_MASTER)
			if (ics->master)
				ics = ERR_PTR(-EBUSY);
			else
				ics->master = 1;
		else
			if (ics->slave)
				ics = ERR_PTR(-EBUSY);
			else
				ics->slave = 1;

		goto out;
	}

	ics = kmalloc(sizeof(struct if_connections), GFP_ATOMIC);
	if (!ics) {
		ics = ERR_PTR(-ENOMEM);
		goto out;
	}

	init_if_connections(ics);

	ics->idx = *idx;
	if (flags & IS_MASTER)
		ics->master = 1;
	else
		ics->slave = 1;
	ics->vmcs = vmcs;
	list_add_tail(&ics->list, &vmcs->vm_ics);

out:
	spin_unlock(&vmcs->lock);
	return ics;
}

static void free_vm_connections(struct kref *ref)
{
	struct vm_connections *vmcs;

	vmcs = container_of(ref, struct vm_connections, ref);
	kfree(vmcs);
}

void put_vm_connections(struct vm_connections *vmcs)
{
	kref_put(&vmcs->ref, free_vm_connections);
}
EXPORT_SYMBOL(put_vm_connections);

void free_if_connections(struct if_connections *ics, int flags)
{
	struct vm_connections *vmcs = ics->vmcs;
	bool free_vmcs = false;

	spin_lock(&vmcs->lock);

	if (flags & IS_MASTER && ics->master) {
		ics->master = 0;
	} else if (!(flags & IS_MASTER) && ics->slave) {
		ics->slave = 0;
	} else {
		goto out;
	}

	if (!ics->master && !ics->slave) {
		list_del_init(&ics->list);
		destroy_connections(ics, flags | DESTROY);
		list_del_init(&ics->list);
		kfree(ics);
	} else
		destroy_connections(ics, flags);

out:
	if (list_empty(&vmcs->vm_ics)) {
		free_vmcs = true;
		spin_lock(&vm_lock);
		list_del_init(&vmcs->vm_entry);
		spin_unlock(&vm_lock);
	}
	spin_unlock(&vmcs->lock);

	if (free_vmcs)
		put_vm_connections(vmcs);
}

struct vm_connections *get_vm_connections(int vm_idx)
{
	struct vm_connections *vmcs;

	spin_lock(&vm_lock);
	list_for_each_entry(vmcs, &vm_list, vm_entry) {
		if (vmcs->vm_idx == vm_idx) {
			kref_get(&vmcs->ref);
			spin_unlock(&vm_lock);
			return vmcs;
		}
	}
	spin_unlock(&vm_lock);

	return NULL;
}
EXPORT_SYMBOL(get_vm_connections);

void __init connections_init(void)
{
	spin_lock_init(&vm_lock);
}
