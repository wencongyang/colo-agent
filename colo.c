/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Implement a qdisc to capture the packets from master and slave.
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
#include <net/pkt_sched.h>

#include "comm.h"
#include "ipv4_fragment.h"
#include "connections.h"
#include "compare_device.h"

enum {
	TCA_COLO_UNSPEC,
	TCA_COLO_DEV_IDX,
	TCA_COLO_FLAGS,
	TCA_COLO_VM_IDX,
	__TCA_COLO_MAX,
};

//#define TCA_COLO_MAX	(__TCA_COLO_MAX - 1)
#define TCA_COLO_MAX 10

/* qidsc: colo */

static inline int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}

static int colo_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct colo_sched_data *q = qdisc_priv(sch);
	struct connect_info *conn_info;
	int wakeup;
	struct vm_connections *vmcs = q->ics->vmcs;

	if (!skb_remove_foreign_references(skb)) {
		pr_err("error removing foreign ref\n");
		goto error;
	}

	conn_info = insert(q->ics, skb, q->flags);
	if (IS_ERR_OR_NULL(conn_info))
		if (PTR_ERR(conn_info) != -EINPROGRESS)
			goto error;

	sch->qstats.backlog += qdisc_pkt_len(skb);
	sch->bstats.bytes += qdisc_pkt_len(skb);
	sch->bstats.packets++;
	sch->q.qlen++;
	if (PTR_ERR(conn_info) == -EINPROGRESS)
		goto out;

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	spin_lock(&vmcs->compare_lock);
	wakeup = list_empty(&vmcs->compare_head);
	if (list_empty(&conn_info->compare_list))
		list_add_tail(&conn_info->compare_list, &vmcs->compare_head);
	spin_unlock(&vmcs->compare_lock);
	if (wakeup)
		wake_up_interruptible(&vmcs->compare_queue);

out:
	return NET_XMIT_SUCCESS;

error:
	return qdisc_reshape_fail(skb, sch);
}

static struct sk_buff *colo_dequeue(struct Qdisc* sch)
{
	struct colo_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = skb_dequeue(&q->rel);

	if (!(q->flags & IS_MASTER)) {
		while (likely(skb)) {
			/* Slaver: Free all packets. */
			sch->qstats.backlog -= qdisc_pkt_len(skb);
			kfree_skb(skb);
			sch->q.qlen--;
			skb = skb_dequeue(&q->rel);
		}
	}

	if (skb) {
		sch->q.qlen--;
		sch->qstats.backlog -= qdisc_pkt_len(skb);
	}
	return skb;
}

static int colo_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct colo_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_COLO_MAX + 1];
	int err;
	struct colo_idx *idx;
	uint32_t *flags, *vm_idx;

	pr_debug("colo init\n");
	err = nla_parse_nested(tb, TCA_COLO_MAX, opt, NULL);
	if (err)
		return err;

	if (!tb[TCA_COLO_DEV_IDX] || !tb[TCA_COLO_FLAGS] ||
	    !tb[TCA_COLO_VM_IDX]) {
		pr_err("missing parameter\n");
		return -EINVAL;
	}

	flags = nla_data(tb[TCA_COLO_FLAGS]);
	idx = nla_data(tb[TCA_COLO_DEV_IDX]);
	vm_idx = nla_data(tb[TCA_COLO_VM_IDX]);
	if (!(*flags & IS_MASTER)) {
		idx->master_idx = idx->master_idx ^ idx->slave_idx;
		idx->slave_idx = idx->master_idx ^ idx->slave_idx;
		idx->master_idx = idx->master_idx ^ idx->slave_idx;
	}
	pr_info("vm: %d, master_idx is: %d, slave_idx is: %d, flags: %02x\n",
		*vm_idx, idx->master_idx, idx->slave_idx, *flags);

	q->ics = alloc_if_connections(idx, *flags, *vm_idx);
	if (IS_ERR(q->ics))
		return PTR_ERR(q->ics);

	if (*flags & IS_MASTER)
		q->ics->master_data = q;
	else
		q->ics->slave_data = q;
	skb_queue_head_init(&q->rel);
	q->sch = sch;
	q->flags = *flags;
	init_ip_frags(&q->ipv4_frags);

	return 0;
}

static void colo_fini(struct Qdisc *sch)
{
	struct colo_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	clear_ipv4_frags(&q->ipv4_frags);
	free_if_connections(q->ics, q->flags);
	while ((skb = skb_dequeue(&q->rel)) != NULL)
		kfree_skb(skb);
}

struct Qdisc_ops colo_qdisc_ops = {
	.id          =       "colo",
	.priv_size   =       sizeof(struct colo_sched_data),
	.enqueue     =       colo_enqueue,
	.dequeue     =       colo_dequeue,
	.peek        =       qdisc_peek_head,
	.init        =       colo_init,
	.destroy     =       colo_fini,
	.owner       =       THIS_MODULE,
};

static int __init colo_module_init(void)
{
	int ret;

	connections_init();
	ipv4_frags_init();
	ret = register_qdisc(&colo_qdisc_ops);
	if (ret)
		return ret;

	ret = colo_dev_init();
	if (ret)
		goto err_dev_init;

	return 0;

err_dev_init:
	unregister_qdisc(&colo_qdisc_ops);
	return ret;
}

static void __exit colo_module_exit(void)
{
	colo_dev_fini();
	unregister_qdisc(&colo_qdisc_ops);
}
module_init(colo_module_init)
module_exit(colo_module_exit)
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
