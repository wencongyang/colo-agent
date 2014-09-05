/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  debugfs to get statistics.
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>

#include "connections.h"
#include "comm.h"

static struct dentry *colo_root_dir;

/* ops for read/write u64 */
/* older kernel doesn't have simple_open */
int __weak simple_open(struct inode *inode, struct file *file)
{
	if (inode->i_private)
		file->private_data = inode->i_private;
	return 0;
}

static ssize_t
simple_read(struct file *filp, char __user *ubuf,
	    size_t cnt, loff_t *ppos)
{
	unsigned long long *data = filp->private_data;
	char buf[64];
	int len;

	len = sprintf(buf, "%lld\n", *data);

	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);
}

static ssize_t
simple_write(struct file *filp, const char __user *ubuf,
	     size_t cnt, loff_t *ppos)
{
	unsigned long long *data = filp->private_data;
	unsigned long long new_value;
	int ret;

	ret = kstrtoull_from_user(ubuf, cnt, 10, &new_value);
	if (ret)
		return ret;

	/* only 0 can be written to clear statistics */
	if (new_value)
		return -EINVAL;

	*data = 0;

	return cnt;
}

const struct file_operations colo_u64_ops = {
	.open		= simple_open,
	.read		= simple_read,
	.write		= simple_write,
	.llseek		= generic_file_llseek,
};
EXPORT_SYMBOL(colo_u64_ops);

/* ops for status file */
static int compare_status_show(struct seq_file *m, void *data)
{
	struct vm_connections *vmcs = m->private;
	struct if_connections *ics;
	struct sk_buff *skb;
	int i;
	struct colo_sched_data *master_queue;
	struct colo_sched_data *slave_queue;
	struct connect_info *conn_info;
	bool m_queue = false, m_rel = false;
	bool s_queue = false, s_rel = false;

	spin_lock(&vmcs->lock);
	list_for_each_entry(ics, &vmcs->vm_ics, list) {
		master_queue = ics->master_data;
		slave_queue = ics->slave_data;

		if (m_queue && s_queue)
			goto skip_queue;

		for (i = 0; i < HASH_NR; i++) {
			list_for_each_entry(conn_info, &ics->entry[i], list) {
				skb = skb_peek(&conn_info->master_queue);
				if (skb != NULL)
					m_queue = true;
				skb = skb_peek(&conn_info->slave_queue);
				if (skb != NULL)
					s_queue = true;

				if (m_queue && s_queue)
					break;
			}
			if (m_queue && s_queue)
				break;
		}

skip_queue:
		if (m_rel && s_rel)
			goto skip_rel;

		skb = skb_peek(&master_queue->rel);
		if (skb != NULL)
			m_rel = true;
		skb = skb_peek(&slave_queue->rel);
		if (skb != NULL)
			s_rel = true;

skip_rel:
		if (m_queue && s_queue && m_rel && s_rel)
			break;
	}

	spin_unlock(&vmcs->lock);

	if (m_queue)
		seq_printf(m, "master compare queueis not empty.\n");
	if (m_rel)
		seq_printf(m, "master release queue is not empty.\n");
	if (s_queue)
		seq_printf(m, "slave compare queue is not empty.\n");
	if (s_rel)
		seq_printf(m, "slave release queue is not empty.\n");

	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, compare_status_show, inode->i_private);
}

static const struct file_operations colo_status_ops = {
	.open		= status_open,
	.read		= seq_read,
	.llseek		= generic_file_llseek,
	.release	= single_release,
};

struct dentry *
colo_create_file(const char *name, const struct file_operations *ops,
		 struct dentry *parent, void *data)
{
	if (!parent)
		parent = colo_root_dir;

	return debugfs_create_file(name, 0644, parent, data, ops);
}

void colo_remove_file(struct dentry *entry)
{
	debugfs_remove(entry);
}

struct dentry * colo_create_dir(const char *name, struct dentry *parent)
{
	if (!parent)
		parent = colo_root_dir;

	return debugfs_create_dir(name, parent);
}

EXPORT_SYMBOL(colo_create_file);
EXPORT_SYMBOL(colo_remove_file);
EXPORT_SYMBOL(colo_create_dir);

struct dentry *colo_add_status_file(const char *name,
				    struct vm_connections *vmcs)
{
	return debugfs_create_file(name, 0444, colo_root_dir,
				   vmcs, &colo_status_ops);
}

int __init colo_debugfs_init(void)
{
	colo_root_dir = debugfs_create_dir("colo", NULL);
	if (!colo_root_dir)
		return -ENOMEM;

	if (IS_ERR(colo_root_dir))
		return PTR_ERR(colo_root_dir);

	return 0;
}

void colo_debugfs_fini(void)
{
	debugfs_remove(colo_root_dir);
}
