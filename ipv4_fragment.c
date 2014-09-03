/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Hanlde the ipv4 fragment
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
#include <linux/jhash.h>
#include <linux/ip.h>
#include <net/ip.h>

#include "comm.h"

#define IPV4_FRAGS_HASHSZ	1024
#define IPVR_FRAGS_TIMEOUT	500

struct ipv4_queue {
	struct ip_frag_queue q;

	u32		user;
	__be32		saddr;
	__be32		daddr;
	__be16		id;
	u8		protocol;
//	u8		ecn; /* RFC3168 support */
};

#define NEW_KERNEL
#ifdef NEW_KERNEL
#define __hlist_for_each_entry(pos, head, member)	\
	hlist_for_each_entry(pos, head, member)
#else
#define __hlist_for_each_entry(pos, head, member)	\
	struct hlist_node *tmp;				\
	hlist_for_each_entry(pos, tmp, head, member)
#endif

static unsigned int ipqhashfn(__be16 id, __be32 saddr, __be32 daddr, u8 prot)
{
	return jhash_3words((__force u32)id << 16 | prot,
			    (__force u32)saddr, (__force u32)daddr,
			    JHASH_INITVAL) & (IPV4_FRAGS_HASHSZ - 1);
}

static struct ip_frag_bucket ipv4_frags[IPV4_FRAGS_HASHSZ];
static void ipv4_frag_expire(unsigned long data);

static inline void put_frag_queue(struct ip_frag_queue *q)
{
	if (atomic_dec_and_test(&q->refcnt)) {
		destroy_frag_queue(q);
		kfree(q);
	}
}

static int ipv4_match_queue(struct ip_frag_queue *q, struct ipv4_queue *ipq_in)
{
	struct ipv4_queue *ipq = container_of(q, struct ipv4_queue, q);

	return	ipq->id == ipq_in->id &&
		ipq->saddr == ipq_in->saddr &&
		ipq->daddr == ipq_in->daddr &&
		ipq->protocol == ipq_in->protocol;
}

static int ipv4_match(struct ip_frag_queue *q, struct iphdr *iph)
{
	struct ipv4_queue *ipq = container_of(q, struct ipv4_queue, q);

	return	ipq->id == iph->id &&
		ipq->saddr == iph->saddr &&
		ipq->daddr == iph->daddr &&
		ipq->protocol == iph->protocol;
}

static void ipv4_frag_expire(unsigned long data)
{
	struct ip_frag_queue *q = (struct ip_frag_queue *)data;

	spin_lock(&q->lock);

	if (q->last_in & INET_FRAG_COMPLETE)
		goto out;

	kill_frag_queue(q);

out:
	spin_unlock(&q->lock);
	put_frag_queue(q);
	return;
}

static struct ipv4_queue *ipv4_frag_intern(struct ipv4_queue *ipq_in,
					   struct iphdr *ip,
					   struct ip_frags *ip_frags,
					   unsigned int hash)
{
	struct ip_frag_bucket *hb;
	struct ip_frag_queue *q, *q_in;

	hb = &ipv4_frags[hash];
	q_in = &ipq_in->q;
	spin_lock(&hb->chain_lock);

#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * released the hash bucket lock.
	 */
	{
		__hlist_for_each_entry(q, &hb->chain, list) {
			if (q->ip_frags == ip_frags &&
			    ipv4_match_queue(q, ipq_in)) {
				atomic_inc(&q->refcnt);
				spin_unlock(&hb->chain_lock);
				q_in->last_in |= INET_FRAG_COMPLETE;
				put_frag_queue(q_in);
				return container_of(q, struct ipv4_queue, q);
			}
		}
	}
#endif
	q = q_in;
	if (!mod_timer(&q->timer, jiffies + IPVR_FRAGS_TIMEOUT))
		atomic_inc(&q->refcnt);

	atomic_inc(&q->refcnt);
	hlist_add_head(&q->list, &hb->chain);
	q->hb = hb;
	spin_unlock(&hb->chain_lock);
	ip_frag_lru_add(ip_frags, q);
	return container_of(q, struct ipv4_queue, q);
}

static struct ipv4_queue *ipv4_frag_alloc(struct iphdr *ip, struct ip_frags *ip_frags)
{
	struct ipv4_queue *ipq;
	struct ip_frag_queue *q;

	ipq = kzalloc(sizeof(*ipq), GFP_ATOMIC);
	if (!ipq)
		return NULL;

	q = &ipq->q;
	q->ip_frags = ip_frags;
	setup_timer(&q->timer, ipv4_frag_expire, (unsigned long)q);
	spin_lock_init(&q->lock);
	atomic_set(&q->refcnt, 1);
	INIT_LIST_HEAD(&q->lru_list);
	INIT_HLIST_NODE(&q->list);

	ipq->saddr = ip->saddr;
	ipq->daddr = ip->daddr;
	ipq->id = ip->id;
	ipq->protocol = ip->protocol;

	return ipq;
}

static struct ipv4_queue *ipv4_frag_create(struct iphdr *ip,
					   struct ip_frags *data,
					   unsigned int hash)
{
	struct ipv4_queue *ipq;

	ipq = ipv4_frag_alloc(ip, data);
	if (!ipq)
		return NULL;

	return ipv4_frag_intern(ipq, ip, data, hash);
}

static struct ipv4_queue *ipv4_find(struct iphdr *ip, struct ip_frags *ip_frags)
{
	struct ip_frag_queue *q;
	unsigned int hash;
	struct ip_frag_bucket *hb;

	hash = ipqhashfn(ip->id, ip->saddr, ip->daddr, ip->protocol);
	hb = &ipv4_frags[hash];

	spin_lock(&hb->chain_lock);
	{
		__hlist_for_each_entry(q, &hb->chain, list) {
			if (q->ip_frags == ip_frags && ipv4_match(q, ip)) {
				atomic_inc(&q->refcnt);
				spin_unlock(&hb->chain_lock);
				return container_of(q, struct ipv4_queue, q);
			}
		}
	}
	spin_unlock(&hb->chain_lock);

	return ipv4_frag_create(ip, ip_frags, hash);
}

static struct sk_buff *ip_frag_reasm(struct ipv4_queue *ipq)
{
	struct sk_buff *skb = ipq->q.fragments;

	kill_frag_queue(&ipq->q);

	WARN_ON(skb_shinfo(skb)->frag_list != NULL);

	skb_shinfo(skb)->frag_list = skb->next;
	skb->next = NULL;

	ipq->q.fragments = NULL;
	ipq->q.fragments_tail = NULL;

	return skb;
}

static struct sk_buff *ipv4_frag_queue(struct ipv4_queue *ipq,
				       struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	int flags, offset, tot_len;
	int ihl, end;
	int err = -ENOENT;

	spin_lock(&ipq->q.wlock);
	if (ipq->q.last_in & INET_FRAG_COMPLETE)
		goto err;

	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);
	tot_len = ntohs(ip_hdr(skb)->tot_len);

	/* Determine the position of this fragment. */
	end = offset + tot_len - ihl;
	err = -EINVAL;

	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrupted.
		 */
		if (end < ipq->q.len ||
		    ((ipq->q.last_in & INET_FRAG_LAST_IN) && end != ipq->q.len))
			goto err;
		ipq->q.last_in |= INET_FRAG_LAST_IN;
		ipq->q.len = end;
	} else {
		if (end&7)
			end &= ~7;

		if (end > ipq->q.len) {
			/* Some bits beyond end -> corruption. */
			if (ipq->q.last_in & INET_FRAG_LAST_IN)
				goto err;
			ipq->q.len = end;
		}
	}
	if (end == offset)
		goto err;

	err = -ENOMEM;

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment, right?
	 */
	prev = ipq->q.fragments_tail;
	if (!prev || FRAG_CB(prev)->offset < offset) {
		next = NULL;
		goto found;
	}
	prev = NULL;
	for (next = ipq->q.fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)
			break;	/* bingo! */
		prev = next;
	}

found:
	/* We found where to put this one. Check for overlap with
	 * preceding fragment, and, if needed, align things so that
	 * any overlaps are eliminated.
	 */
	if (prev) {
		int i = (FRAG_CB(prev)->offset + FRAG_CB(prev)->len) - offset;

		if (i > 0) {
			offset += i;
			err = -EINVAL;
			if (end <= offset)
				goto err;
		}
	}

	err = -ENOMEM;

	while (next && FRAG_CB(next)->offset < end) {
		int i = end - FRAG_CB(next)->offset; /* overlap is 'i' bytes */

		if (i < FRAG_CB(next)->len) {
			/* Eat head of the next overlapped fragment
			 * and leave the loop. The next ones cannot overlap.
			 */
			FRAG_CB(next)->offset += i;
			FRAG_CB(next)->len -= i;
			ipq->q.meat -= i;
			break;
		} else {
			struct sk_buff *free_it = next;

			/* Old fragment is completely overridden with
			 * new one drop it.
			 */
			next = next->next;

			if (prev)
				prev->next = next;
			else
				ipq->q.fragments = next;

			ipq->q.meat -= FRAG_CB(skb)->len;
			kfree_skb(free_it);
		}
	}

	FRAG_CB(skb)->offset = offset;
	FRAG_CB(skb)->len = end - offset;

	/* Insert this fragment in the chain of fragments. */
	skb->next = next;
	if (!next)
		ipq->q.fragments_tail = skb;
	if (prev)
		prev->next = skb;
	else
		ipq->q.fragments = skb;

	ipq->q.meat += FRAG_CB(skb)->len;
	if (offset == 0)
		ipq->q.last_in |= INET_FRAG_FIRST_IN;

	if (ipq->q.last_in == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    ipq->q.meat == ipq->q.len) {
		FRAG_CB(ipq->q.fragments)->tot_len = ipq->q.len;
		spin_unlock(&ipq->q.wlock);
		return ip_frag_reasm(ipq);
	}

	spin_unlock(&ipq->q.wlock);
	ip_frag_lru_move(&ipq->q);
	return ERR_PTR(-EINPROGRESS);

err:
	spin_unlock(&ipq->q.wlock);
	return ERR_PTR(err);
}

struct sk_buff *ipv4_defrag(struct sk_buff *skb, struct ip_frags *data)
{
	struct ipv4_queue *ipv4_q = ipv4_find(ip_hdr(skb), data);

	if (ipv4_q) {
		struct sk_buff *ret;

		spin_lock(&ipv4_q->q.lock);
		ret = ipv4_frag_queue(ipv4_q, skb);
		spin_unlock(&ipv4_q->q.lock);

		put_frag_queue(&ipv4_q->q);
		return ret;
	}

	return ERR_PTR(-ENOMEM);
}

static struct ip_frag_queue *copy_ipv4_queue(struct ipv4_queue *src_ipq)
{
	struct ipv4_queue *dst_ipq;
	int ret;

	dst_ipq = kzalloc(sizeof(*dst_ipq), GFP_KERNEL);
	if (!dst_ipq)
		return NULL;

	dst_ipq->saddr = src_ipq->saddr;
	dst_ipq->daddr = src_ipq->daddr;
	dst_ipq->id = src_ipq->id;
	dst_ipq->protocol = src_ipq->protocol;

	setup_timer(&dst_ipq->q.timer, ipv4_frag_expire, (unsigned long)&dst_ipq->q);
	ret = copy_frag_queue(&src_ipq->q, &dst_ipq->q);
	if (ret != 0)
		goto err;

	return &dst_ipq->q;

err:
	kfree(dst_ipq);
	return NULL;
}

#define lock_two_locks(lock1, lock2)					\
	do {								\
		if ((unsigned long)lock1 <= (unsigned long)lock2) {	\
			spin_lock_bh(lock1);				\
			spin_lock(lock2);				\
		} else {						\
			spin_lock_bh(lock2);				\
			spin_lock(lock1);				\
		}							\
	} while (0)

#define unlock_two_locks(lock1, lock2)					\
	do {								\
		spin_unlock(lock1);					\
		spin_unlock_bh(lock2);					\
	} while (0)

void copy_ipv4_frags(struct ip_frags *src_ip_frags,
		     struct ip_frags *dst_ip_frags)
{
	struct ipv4_queue *ipq;
	struct ip_frag_queue *q, *new_q;

	lock_two_locks(&src_ip_frags->lru_lock, &dst_ip_frags->lru_lock);
	list_for_each_entry(q, &src_ip_frags->lru_list, lru_list) {
		ipq = container_of(q, struct ipv4_queue, q);
		new_q = copy_ipv4_queue(ipq);
		if (new_q == NULL)
			continue;

		new_q->ip_frags = dst_ip_frags;
		list_add_tail(&new_q->lru_list, &dst_ip_frags->lru_list);
	}
	unlock_two_locks(&src_ip_frags->lru_lock, &dst_ip_frags->lru_lock);
}

void clear_ipv4_frags(struct ip_frags *ip_frags)
{
	struct ip_frag_queue *q, *tmp;
	struct list_head tmp_list;

	INIT_LIST_HEAD(&tmp_list);
	spin_lock_bh(&ip_frags->lru_lock);
	list_for_each_entry_safe(q, tmp, &ip_frags->lru_list, lru_list) {
		list_del_init(&q->lru_list);
		q->ip_frags->nqueues--;

		/* remove it from hash list */
		spin_lock(&q->hb->chain_lock);
		hlist_del_init(&q->list);
		spin_unlock(&q->hb->chain_lock);

		atomic_inc(&q->refcnt);
		list_add_tail(&q->lru_list, &tmp_list);
	}
	spin_unlock_bh(&ip_frags->lru_lock);

	list_for_each_entry_safe(q, tmp, &tmp_list, lru_list) {
		list_del_init(&q->lru_list);
		spin_lock(&q->lock);
		if (!(q->last_in & INET_FRAG_COMPLETE))
			kill_frag_queue(q);
		spin_unlock(&q->lock);
		put_frag_queue(q);
	}
}

EXPORT_SYMBOL(copy_ipv4_frags);
EXPORT_SYMBOL(clear_ipv4_frags);

void ipv4_frags_init(void)
{
	int i;

	for (i = 0; i < IPV4_FRAGS_HASHSZ; i++) {
		INIT_HLIST_HEAD(&ipv4_frags[i].chain);
		spin_lock_init(&ipv4_frags[i].chain_lock);
	}
}

/* common functions for comparing ipv4 fragments */
struct sk_buff *ipv4_get_skb_by_offset(struct sk_buff *head, int offset)
{
	struct sk_buff *skb = head;
	int frag_offset, frag_len;

	do {
		frag_offset = FRAG_CB(head)->offset;
		frag_len = FRAG_CB(head)->len;
		if (frag_offset <= offset && frag_offset + frag_len > offset)
			return skb;

		if (skb == head)
			skb = skb_shinfo(skb)->frag_list;
		else
			skb = skb->next;
	} while (skb != NULL);

	return NULL;
}

void *ipv4_get_data(struct sk_buff *skb, int offset)
{
	void *data = (void *)(ip_hdr(skb)->ihl * 4 + (char *)ip_hdr(skb));
	int frag_offset;

	frag_offset = ntohs(ip_hdr(skb)->frag_off);
	frag_offset &= IP_OFFSET;
	frag_offset <<= 3;

	if (frag_offset < FRAG_CB(skb)->offset)
		data += FRAG_CB(skb)->offset - frag_offset;

	if (offset > FRAG_CB(skb)->offset)
		data += offset - FRAG_CB(skb)->offset;

	return data;
}

int ipv4_copy_transport_head(void *data, struct sk_buff *head, int size)
{
	struct sk_buff *skb = head;
	void *src = ipv4_get_data(skb, 0);
	int len;

	do {
		len = FRAG_CB(skb)->len;
		len = len > size ? size : len;
		memcpy(data, src, len);
		size -= len;

		if (size == 0)
			return 0;

		skb = next_skb(skb, head);
		if (!skb)
			break;
		src = ipv4_get_data(skb, FRAG_CB(skb)->offset);
	} while(skb != NULL);

	return 1;
}

EXPORT_SYMBOL(ipv4_get_skb_by_offset);
EXPORT_SYMBOL(ipv4_get_data);
EXPORT_SYMBOL(ipv4_copy_transport_head);
