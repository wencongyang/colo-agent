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

#ifndef IP_FRAGMENT_H
#define IP_FRAGMENT_H

/*
 * lock order:
 *    1. ip_frag_queue.lock
 *    2. ip_frags.lru_lock
 *    3. ip_frag_bucket.chain_lock
 *    4. ip_frag_queue.wlock
 */

struct ip_frag_bucket {
	struct hlist_head chain;
	spinlock_t chain_lock;
};

struct ip_frags {
	int nqueues;
	struct list_head lru_list;
	spinlock_t lru_lock;
};

struct ip_frag_queue {
	spinlock_t		lock;

	/*
	 * use wlock to avoid deadlock, handle ip fragments in this order:
	 *   1. lock ip_frag_queue.lock
	 *   2. lock ip_frag_queue.wlock
	 *   3. update ip_frag_queue
	 *   4. unlock ip_frag_queue.wlock
	 *   5. do other things
	 *   6. unlock frag_queu.lock
	 */
	spinlock_t		wlock;
	struct timer_list	timer;      /* when will this queue expire? */
	struct list_head	lru_list;   /* lru list member */
	struct hlist_node	list;
	atomic_t		refcnt;
	struct sk_buff		*fragments; /* list of received fragments */
	struct sk_buff		*fragments_tail;
	int			len;        /* total length of orig datagram */
	int			meat;
	__u8			last_in;    /* first/last segment arrived? */

	struct ip_frags		*ip_frags;
	struct ip_frag_bucket	*hb;
};

struct ipfrag_skb_cb
{
	unsigned int		flags;
	int			offset;
	int			len;

	/* Only for fragment0 */
	int			tot_len;
};

#define FRAG_CB(skb)	((struct ipfrag_skb_cb *)((skb)->cb))

/* ipfrag_skb_cb.flags */
#define IS_FRAGMENT		(1 << 0)

static inline void init_ip_frags(struct ip_frags *ip_frags)
{
	ip_frags->nqueues = 0;
	INIT_LIST_HEAD(&ip_frags->lru_list);
	spin_lock_init(&ip_frags->lru_lock);
}

static inline void ip_frag_lru_del(struct ip_frag_queue *q)
{
	spin_lock(&q->ip_frags->lru_lock);
	if (!list_empty(&q->lru_list)) {
		list_del_init(&q->lru_list);
		q->ip_frags->nqueues--;
	}
	spin_unlock(&q->ip_frags->lru_lock);
}

static inline void ip_frag_lru_add(struct ip_frags *ip_frags,
				   struct ip_frag_queue *q)
{
	spin_lock(&ip_frags->lru_lock);
	list_add_tail(&q->lru_list, &ip_frags->lru_list);
	ip_frags->nqueues++;
	spin_unlock(&ip_frags->lru_lock);
}

static inline void ip_frag_lru_move(struct ip_frag_queue *q)
{
	spin_lock(&q->ip_frags->lru_lock);
	if (!list_empty(&q->lru_list))
		list_move_tail(&q->lru_list, &q->ip_frags->lru_list);
	spin_unlock(&q->ip_frags->lru_lock);
}

static inline void fq_unlink(struct ip_frag_queue *q, struct ip_frag_bucket *hb)
{
	/* remove ip_frag_queue from ip_frags first, so it can be copied safely */
	ip_frag_lru_del(q);

	spin_lock(&hb->chain_lock);
	hlist_del_init(&q->list);
	spin_unlock(&hb->chain_lock);
}

static inline struct sk_buff *next_skb(struct sk_buff *skb, struct sk_buff *head)
{
	if (skb == head)
		return skb_shinfo(skb)->frag_list;
	else
		return skb->next;
}

/* q.lock should be hold and q.wlock should not be hold */
extern void kill_frag_queue(struct ip_frag_queue *q);

/* free all skb in ip_frag_queue */
extern void destroy_frag_queue(struct ip_frag_queue *q);

/* src and dst ip_frags.lock should be hold, dst_q->timer should be setup */
extern int copy_frag_queue(struct ip_frag_queue *src_q, struct ip_frag_queue *dst_q);
#endif
