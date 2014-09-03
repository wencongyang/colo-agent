/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Hanlde the ip fragment for ipv4 and ipv6(not implemented)
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
#include <linux/skbuff.h>
#include <net/inet_frag.h>

#include "ip_fragment.h"

void kill_frag_queue(struct ip_frag_queue *q)
{
	if (del_timer(&q->timer))
		atomic_dec(&q->refcnt);

	if (!(q->last_in & INET_FRAG_COMPLETE)) {
		fq_unlink(q, q->hb);
		atomic_dec(&q->refcnt);
		q->last_in |= INET_FRAG_COMPLETE;
	}
}

void destroy_frag_queue(struct ip_frag_queue *q)
{
	struct sk_buff *skb;

	WARN_ON(!(q->last_in & INET_FRAG_COMPLETE));
	WARN_ON(del_timer(&q->timer) != 0);

	skb = q->fragments;
	while (skb) {
		struct sk_buff *next = skb->next;

		/* We can see skb only when timer expires */
		kfree_skb(skb);
		skb = next;
	}
}

/*
 * This API is for copying fragments from master to slave. It is called
 * under the lock ip_frags.lock. src_q is in the list ip_frags.lru_list,
 * so it cannot be destroyed.
 */
int copy_frag_queue(struct ip_frag_queue *src_q, struct ip_frag_queue *dst_q)
{
	struct sk_buff *src_skb, *dst_skb;
	unsigned int expire_time;

	spin_lock_init(&dst_q->lock);
	spin_lock_init(&dst_q->wlock);

	spin_lock_bh(&src_q->wlock);
	if (unlikely(src_q->last_in & INET_FRAG_COMPLETE))
		goto skip;

	/* copy skb list */
	src_skb = src_q->fragments;
	dst_skb = NULL;
	while (src_skb != NULL) {
		dst_skb = skb_clone(src_skb, GFP_ATOMIC);
		if (!dst_skb)
			goto err;

		if (dst_q->fragments == NULL)
			dst_q->fragments = dst_skb;
		src_skb = src_skb->next;
	};
	dst_q->fragments_tail = dst_skb;
	dst_q->meat = src_q->meat;
	dst_q->len = src_q->len;
	dst_q->last_in = src_q->last_in;
	dst_q->hb = src_q->hb;
	expire_time = src_q->timer.expires;
	spin_unlock_bh(&src_q->wlock);

	atomic_set(&dst_q->refcnt, 1);

	/* We remove ip_frag_queue from ip_frags before removing it from hb */
	spin_lock_bh(&src_q->hb->chain_lock);
	hlist_add_after(&src_q->list, &dst_q->list);
	spin_unlock_bh(&src_q->hb->chain_lock);

	if (mod_timer(&dst_q->timer, expire_time))
		atomic_inc(&dst_q->refcnt);

	return 0;

skip:
	spin_unlock_bh(&src_q->wlock);
	return 1;

err:
	spin_unlock_bh(&src_q->wlock);
	dst_q->last_in |= INET_FRAG_COMPLETE;
	destroy_frag_queue(dst_q);
	return -1;
}
