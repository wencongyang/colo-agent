/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  A device for the usespace to control comparing and wait checkpoint
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
#include <linux/cdev.h>
#include <linux/skbuff.h>
#include <linux/anon_inodes.h>
#include <linux/kthread.h>

#include "comm.h"
#include "compare.h"
#include "compare_device.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

#define COMP_IOC_MAGIC          'k'
#define COMP_IOCTWAIT           _IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTFLUSH          _IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME         _IO(COMP_IOC_MAGIC, 2)

#define COLO_IO                 0x33
#define COLO_CREATE_VM          _IO(COLO_IO, 0x00)
#define COLO_RELEASE_VM         _IO(COLO_IO, 0x01)

#define EXPIRE_TIME             60
static int expire_time;

struct colo_vm {
	struct vm_connections *vmcs;
	struct task_struct *compare_thread;
	int vm_idx;
	atomic_t count;
};

static void colo_put_vm(struct colo_vm *colo_vm);

static void clear_slave_queue(struct if_connections *ics)
{
	int i;
	struct sk_buff *skb;
	struct connect_info *conn_info, *temp;
	struct vm_connections *vmcs = ics->vmcs;

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry_safe(conn_info, temp, &ics->entry[i], list) {
			skb = skb_dequeue(&conn_info->slave_queue);
			while (skb != NULL) {
				skb_queue_tail(&conn_info->ics->slave_data->rel, skb);
				skb = skb_dequeue(&conn_info->slave_queue);
			}

			if (jiffies_64 - conn_info->touch_time >= expire_time) {
				skb = skb_peek(&conn_info->master_queue);
				BUG_ON(skb);

				list_del_init(&conn_info->list);
				spin_lock_bh(&vmcs->compare_lock);
				BUG_ON(conn_info->state & IN_COMPARE);
				list_del_init(&conn_info->compare_list);
				spin_unlock_bh(&vmcs->compare_lock);
				kfree(conn_info);
			}
		}
	}

	/* clear ip fragments */
	clear_ipv4_frags(&ics->slave_data->ipv4_frags);

	/* copy ipv4 fragments from master */
	copy_ipv4_frags(&ics->master_data->ipv4_frags,
			&ics->slave_data->ipv4_frags);
}

static void clear_slave_queue_on_vm(struct vm_connections *vmcs)
{
	struct if_connections *ics;

	spin_lock(&vmcs->lock);
	list_for_each_entry(ics, &vmcs->vm_ics, list) {
		clear_slave_queue(ics);
	}
	spin_unlock(&vmcs->lock);
}

static void update_compare_info(struct connect_info *conn_info, struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	void *data;
	const compare_net_ops_t *ops;

	data = skb->data + sizeof(*eth);

	rcu_read_lock();
	ops = get_compare_net_ops(eth->h_proto);
	if (ops && ops->update_info)
		ops->update_info(&conn_info->m_info, data, skb);
	rcu_read_unlock();
}

static void flush_packets(struct connect_info *conn_info)
{
	const compare_net_ops_t *ops;

	if (conn_info->flushed)
		return;

	if (conn_info->key.ip_proto == 0)
		return;

	rcu_read_lock();
	ops = get_compare_net_ops(htons(ETH_P_IP));
	if (ops && ops->flush_packets)
		ops->flush_packets(&conn_info->m_info, conn_info->key.ip_proto);
	rcu_read_unlock();
	conn_info->flushed = 1;
}

static void move_master_queue(struct if_connections *ics)
{
	int i;
	struct sk_buff *skb;
	struct connect_info *conn_info;

	if (unlikely(ics == NULL)) {
		pr_warn("ics is NULL when move_master_queue\n");
		return;
	}

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry(conn_info, &ics->entry[i], list) {
			skb = skb_dequeue(&conn_info->master_queue);
			while (skb != NULL) {
				update_compare_info(conn_info, skb);
				skb_queue_tail(&ics->wait_for_release, skb);
				skb = skb_dequeue(&conn_info->master_queue);
			}

			/*
			 * copy compare info:
			 *      We call this function when a new checkpoint is
			 *      finished. The status of master and slave is
			 *      the same. So slave's compare info shoule be
			 *      the same as master's.
			 */
			memcpy(&conn_info->s_info, &conn_info->m_info,
				sizeof(conn_info->s_info));
			flush_packets(conn_info);
		}
	}
}

static void move_master_queue_on_vm(struct vm_connections *vmcs)
{
	struct if_connections *ics;

	spin_lock(&vmcs->lock);
	list_for_each_entry(ics, &vmcs->vm_ics, list) {
		move_master_queue(ics);
	}
	spin_unlock(&vmcs->lock);
}

static void release_queue(struct if_connections *ics)
{
	struct sk_buff *skb;
	int flag = 0;

	if (unlikely(ics == NULL)) {
		pr_warn("ics is NULL when release queue\n");
		return;
	}

	skb = skb_dequeue(&ics->wait_for_release);
	while (skb != NULL) {
		flag = 1;
		skb_queue_tail(&ics->master_data->rel, skb);
		skb = skb_dequeue(&ics->wait_for_release);
	}

	if (flag)
		netif_schedule_queue(ics->master_data->sch->dev_queue);
}

static void release_queue_on_vm(struct vm_connections *vmcs)
{
	struct if_connections *ics;

	spin_lock(&vmcs->lock);
	list_for_each_entry(ics, &vmcs->vm_ics, list) {
		release_queue(ics);
	}
	spin_unlock(&vmcs->lock);
}

static long colo_cmp_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	int ret;
	unsigned long jiffies;
	struct colo_vm *colo_vm = filp->private_data;

	switch(cmd) {
	case COMP_IOCTWAIT:
		/* wait for a new checkpoint */
		jiffies = msecs_to_jiffies(arg);
		ret = wait_event_interruptible_timeout(
			colo_vm->vmcs->checkpoint_queue,
			state != state_comparing, jiffies);
		if (ret == 0)
			return -ETIME;

		if (ret < 0)
			return -ERESTART;

		pr_notice("HA_compare: --------start a new checkpoint.\n");

		break;
	case COMP_IOCTFLUSH:
		/*  Both sides suspend the VM, at this point, no packets will
		 *  send out from VM, so block skb queues(master&slave) are
		 *  stable. Move master block queue to a temporary queue, then
		 *  they will be released when checkpoint ends. For slave
		 *  block queue, just drop them.
		 */
		pr_notice("HA_compare: --------flush packets.\n");

		move_master_queue_on_vm(colo_vm->vmcs);
		clear_slave_queue_on_vm(colo_vm->vmcs);
		break;
	case COMP_IOCTRESUME:
		/*
		 *  Checkpoint finish, relese skb in temporary queue
		 */
		pr_notice("HA_compare: --------checkpoint finish.\n");
		release_queue_on_vm(colo_vm->vmcs);
		state = state_comparing;

		break;
	}

	return 0;
}

static int colo_cmp_release(struct inode *inode, struct file *filep)
{
	struct colo_vm *colo_vm = filep->private_data;

	colo_put_vm(colo_vm);
	return 0;
}

static struct file_operations colo_cmp_fops = {
	.release = colo_cmp_release,
	.owner = THIS_MODULE,
	.unlocked_ioctl = colo_cmp_ioctl,
};

static void colo_put_vm(struct colo_vm *colo_vm)
{
	if (!atomic_dec_and_test(&colo_vm->count))
		return;

	if (colo_vm->vmcs) {
		spin_lock(&colo_vm->vmcs->lock);
		colo_vm->vmcs->compare_data = NULL;
		spin_unlock(&colo_vm->vmcs->lock);
		put_vm_connections(colo_vm->vmcs);
	}
	kthread_stop(colo_vm->compare_thread);
	kfree(colo_vm);
}

static struct colo_vm *colo_create_vm(int vm_idx)
{
	struct vm_connections *vmcs = get_vm_connections(vm_idx);
	struct colo_vm *colo_vm;
	struct task_struct *compare_thread;

	if (!vmcs)
		return ERR_PTR(-EINVAL);

	colo_vm = kmalloc(sizeof(*colo_vm), GFP_KERNEL);
	if (!colo_vm)
		return ERR_PTR(-ENOMEM);

	compare_thread = kthread_create(compare_kthread, vmcs, "compare/%d",
					vm_idx);
	if (IS_ERR(compare_thread)) {
		kfree(colo_vm);
		pr_err("HA_compare: can't create kernel thread\n");
		return ERR_PTR(-ENOMEM);
	}

	colo_vm->vmcs = NULL;
	colo_vm->vm_idx = vm_idx;
	colo_vm->compare_thread = compare_thread;
	atomic_set(&colo_vm->count, 1);

	spin_lock(&vmcs->lock);

	if (vmcs->compare_data) {
		spin_unlock(&vmcs->lock);
		put_vm_connections(vmcs);
		colo_put_vm(colo_vm);
		return ERR_PTR(-EBUSY);
	}

	vmcs->compare_data = colo_vm;
	spin_unlock(&vmcs->lock);
	colo_vm->vmcs = vmcs;

	wake_up_process(compare_thread);

	return colo_vm;
}

static int
colo_dev_ioctl_create_vm(unsigned long arg, struct colo_vm **colo_vm_p)
{
	int r;
	struct colo_vm *colo_vm;

	colo_vm = colo_create_vm(arg);
	if (IS_ERR(colo_vm))
		return PTR_ERR(colo_vm);

	r = anon_inode_getfd("colo-compare", &colo_cmp_fops, colo_vm,
			     O_RDWR | O_CLOEXEC);

	if (r < 0) {
		colo_put_vm(colo_vm);
	} else {
		atomic_inc(&colo_vm->count);
		*colo_vm_p = colo_vm;
	}

	return r;
}

/* colo char device */
static int colo_dev_release(struct inode *inode, struct file *filp)
{
	if (filp->private_data)
		colo_put_vm(filp->private_data);

	return 0;
}

static long colo_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long r = -EINVAL;
	struct colo_vm *colo_vm = NULL;

	switch(cmd) {
	case COLO_CREATE_VM:
		if (filp->private_data) {
			r = -EBUSY;
			break;
		}

		r = colo_dev_ioctl_create_vm(arg, &colo_vm);
		filp->private_data = colo_vm;
		break;
	case COLO_RELEASE_VM:
		if (!filp->private_data)
			break;

		colo_vm = filp->private_data;
		if (colo_vm->vm_idx != arg)
			break;

		colo_put_vm(colo_vm);
		filp->private_data = NULL;
		r = 0;
		break;
	default:
		break;
	}

	return r;
}

struct file_operations colo_chardev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = colo_dev_ioctl,
	.release = colo_dev_release,
};

static struct miscdevice colo_dev = {
	MISC_DYNAMIC_MINOR,
	"HA_compare",
	&colo_chardev_fops,
};

int colo_dev_init(void)
{
	int ret;

	ret = misc_register(&colo_dev);
	if (ret) {
		pr_err("HA_compare: misc device register failed\n");
		return ret;
	}

	expire_time = msecs_to_jiffies(EXPIRE_TIME * 1000);

	return 0;
}

void colo_dev_fini(void)
{
	misc_deregister(&colo_dev);
}
