/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Compare ipv4 packets from master and slave.
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
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <net/protocol.h>
#include <net/ip.h>

#include "compare.h"
#include "compare_ipv4.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"
#include "connections.h"
#include "comm.h"
#include "compare_debugfs.h"

bool ignore_id = 1;
module_param(ignore_id, bool, 0644);
MODULE_PARM_DESC(ignore_id, "bypass id difference");

const ipv4_compare_ops_t *compare_inet_ops[MAX_INET_PROTOS];
DEFINE_MUTEX(inet_ops_lock);

/* static */
unsigned short last_id = 0;
unsigned int same_count = 0;

/* statistics */
static struct ipv4_statistics {
	unsigned long long m_error_packet;
	unsigned long long s_error_packet;
	unsigned long long ihl;
	unsigned long long options;
	unsigned long long data_len;
	unsigned long long data;
	unsigned long long tos;
	unsigned long long frag_off;
	unsigned long long ttl;
	unsigned long long id;
} statis;

static struct {
	struct dentry *root_entry;
	struct dentry *status_entry;
	struct dentry *m_error_packet_entry;
	struct dentry *s_error_packet_entry;
	struct dentry *ihl_entry;
	struct dentry *options_entry;
	struct dentry *data_len_entry;
	struct dentry *data_entry;
	struct dentry *tos_entry;
	struct dentry *frag_off_entry;
	struct dentry *ttl_entry;
	struct dentry *id_entry;
} statis_entry;

static void ipv4_update_compare_info(void *info, void *data,
				     struct sk_buff *skb);

int register_ipv4_compare_ops(ipv4_compare_ops_t *ops, unsigned short protocol)
{
	mutex_lock(&inet_ops_lock);
	if (compare_inet_ops[protocol]) {
		mutex_unlock(&inet_ops_lock);
		return -1;
	}

	rcu_assign_pointer(compare_inet_ops[protocol], ops);
	mutex_unlock(&inet_ops_lock);

	synchronize_rcu();
	return 0;
}

int unregister_ipv4_compare_ops(ipv4_compare_ops_t *ops, unsigned short protocol)
{
	mutex_lock(&inet_ops_lock);
	if (compare_inet_ops[protocol] != ops) {
		mutex_unlock(&inet_ops_lock);
		return -1;
	}

	rcu_assign_pointer(compare_inet_ops[protocol], NULL);
	mutex_unlock(&inet_ops_lock);

	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL(register_ipv4_compare_ops);
EXPORT_SYMBOL(unregister_ipv4_compare_ops);

static void debug_print_ip(const struct compare_info *cinfo,
			   const struct iphdr *ip)
{
	unsigned short len = ntohs(ip->tot_len);
	unsigned short id = ntohs(ip->id);
	unsigned char protocol = ip->protocol;
	void *data = (char *)ip + ip->ihl * 4;
	const ipv4_compare_ops_t * ops;

	pr_warn("HA_compare:[IP]len = %u, id= %u.\n", len, id);
	len -= ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->debug_print)
		ops->debug_print(cinfo, data, len);
	else
		pr_warn("HA_compare: unknown protocol: %u\n", protocol);
	rcu_read_unlock();
}

static void print_debuginfo(struct compare_info *m_cinfo,
			    struct compare_info *s_cinfo)
{
	pr_warn("HA_compare: same=%u, last_id=%u\n", same_count, last_id);
	pr_warn("HA_compare: Master pkt:\n");
	debug_print_ip(m_cinfo, m_cinfo->ip);
	pr_warn("HA_compare: Slaver pkt:\n");
	debug_print_ip(s_cinfo, s_cinfo->ip);
}

#define ip_is_fragment(iph)	(iph->frag_off & htons(IP_MF | IP_OFFSET))

static uint32_t ipv4_compare_fragment(struct compare_info *m_cinfo,
				      struct compare_info *s_cinfo)
{
	return ipv4_transport_compare_fragment(m_cinfo->skb, s_cinfo->skb, 0, 0,
					       m_cinfo->length);
}

static inline void set_frag_cb(struct compare_info *cinfo)
{
	FRAG_CB(cinfo->skb)->offset = 0;
	FRAG_CB(cinfo->skb)->len = cinfo->length;
	FRAG_CB(cinfo->skb)->tot_len = cinfo->length;

	/* skb is linear, so it is safe to reset frag_list */
	skb_shinfo(cinfo->skb)->frag_list = NULL;
}

static void ipv4_update_packet(struct compare_info *m_cinfo,
			       struct compare_info *s_cinfo,
			       uint8_t protocol, uint32_t ret)
{
	const ipv4_compare_ops_t *ops;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->update_packet)
		ops->update_packet(m_cinfo, s_cinfo, ret);
	else
		pr_warn("update_packet is not supported,"
			" but returns UPDATE_MASTER_PACKET\n");
	rcu_read_unlock();
}

static uint32_t
__ipv4_compare_packet(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	uint32_t ret;
	const ipv4_compare_ops_t *ops;
	bool m_fragment, s_fragment;

	if (unlikely(m_cinfo->ip->ihl * 4 > m_cinfo->length)) {
		pr_warn("HA_compare: master iphdr is corrupted\n");
		statis.m_error_packet++;
		return CHECKPOINT;
	}

	if (unlikely(s_cinfo->ip->ihl * 4 > s_cinfo->length)) {
		pr_warn("HA_compare: slave iphdr is corrupted\n");
		statis.s_error_packet++;
		return CHECKPOINT;
	}

#define compare_elem_l(elem, statis)					\
	do {								\
		if (unlikely(m_cinfo->ip->elem != s_cinfo->ip->elem)) {	\
			pr_warn("HA_compare: iphdr's %s is different\n",\
				#elem);					\
			pr_warn("HA_compare: master %s: %x\n", #elem,	\
				m_cinfo->ip->elem);			\
			pr_warn("HA_compare: slave %s: %x\n", #elem,	\
				s_cinfo->ip->elem);			\
			print_debuginfo(m_cinfo, s_cinfo);		\
			UPDATE_STATIS(statis);				\
			return CHECKPOINT | UPDATE_COMPARE_INFO;	\
		}							\
	} while (0)
#define compare_elem(elem)	compare_elem_l(elem, elem)

	/* version/protocol/saddr/daddr should be the same */
#define UPDATE_STATIS(elem)
	compare_elem(version);
	compare_elem(protocol);
	compare_elem(saddr);
	compare_elem(daddr);

#undef UPDATE_STATIS
#define UPDATE_STATIS(elem)	statis.elem++
	compare_elem(ihl);

	/* IP options */
	if (memcmp((char *)m_cinfo->ip + 20, (char*)s_cinfo->ip + 20,
		   m_cinfo->ip->ihl * 4 - 20)) {
		pr_warn("HA_compare: iphdr option is different\n");
		print_debuginfo(m_cinfo, s_cinfo);
		statis.options++;
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	m_fragment = ip_is_fragment(m_cinfo->ip);
	s_fragment = ip_is_fragment(s_cinfo->ip);
	m_cinfo->ip_data = (char *)m_cinfo->ip + m_cinfo->ip->ihl * 4;
	if (m_fragment)
		m_cinfo->length = FRAG_CB(m_cinfo->skb)->tot_len;
	else if (m_cinfo->length <= ntohs(m_cinfo->ip->tot_len))
		m_cinfo->length -= m_cinfo->ip->ihl * 4;
	else
		m_cinfo->length = ntohs(m_cinfo->ip->tot_len) -
				  m_cinfo->ip->ihl * 4;

	s_cinfo->ip_data = (char *)s_cinfo->ip + s_cinfo->ip->ihl * 4;
	if (s_fragment)
		s_cinfo->length = FRAG_CB(s_cinfo->skb)->tot_len;
	else if (s_cinfo->length <= ntohs(s_cinfo->ip->tot_len))
		s_cinfo->length -= s_cinfo->ip->ihl * 4;
	else
		s_cinfo->length = ntohs(s_cinfo->ip->tot_len) -
				  s_cinfo->ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[m_cinfo->ip->protocol]);
	if (m_fragment || s_fragment) {
		if (ops && ops->compare_fragment) {
			if (!m_fragment)
				set_frag_cb(m_cinfo);
			if (!s_fragment)
				set_frag_cb(s_cinfo);
			ret = ops->compare_fragment(m_cinfo, s_cinfo);
		} else {
			if (m_cinfo->length != s_cinfo->length) {
				pr_warn("HA_compare: the length of packet is different\n");
				pr_warn("  transport protocol: %d\n",
					m_cinfo->ip->protocol);
				print_debuginfo(m_cinfo, s_cinfo);
				rcu_read_unlock();
				statis.data_len++;
				return CHECKPOINT | UPDATE_COMPARE_INFO;
			}
			ret = ipv4_compare_fragment(m_cinfo, s_cinfo);
			if (ret & CHECKPOINT) {
				pr_warn("HA_compare: the data is different\n");
				pr_warn("  transport protocol: %d\n",
					m_cinfo->ip->protocol);
				statis.data++;
			}
		}
	} else {
		if (ops && ops->compare) {
			ret = ops->compare(m_cinfo, s_cinfo);
		} else {
//			pr_info("unknown protocol: %u", ntohs(master->protocol));
			if (m_cinfo->length != s_cinfo->length) {
				pr_warn("HA_compare: the length of packet is different\n");
				pr_warn("  transport protocol: %d\n",
					m_cinfo->ip->protocol);
				print_debuginfo(m_cinfo, s_cinfo);
				rcu_read_unlock();
				statis.data_len++;
				return CHECKPOINT | UPDATE_COMPARE_INFO;
			}
			ret = default_compare_data(m_cinfo->ip_data,
						   s_cinfo->ip_data,
						   m_cinfo->length);
			if (ret & CHECKPOINT) {
				pr_warn("HA_compare: the data is different\n");
				pr_warn("  transport protocol: %d\n",
					m_cinfo->ip->protocol);
				statis.data++;
			}
		}
	}
	rcu_read_unlock();
	if (ret & CHECKPOINT)
		print_debuginfo(m_cinfo, s_cinfo);

	if ((ret & SAME_PACKET) != SAME_PACKET)
		return ret;

	compare_elem(tos);
	if (!(ret & IGNORE_LEN))
		compare_elem_l(tot_len, data_len);
	compare_elem(frag_off);
	compare_elem(ttl);
	if (!ignore_id)
		compare_elem(id);

	/*
	 * No need to compare checksum:
	 *      If ip header without checksum are the same, checksum
	 *      shoule be the same too.
	 */
//	compare_elem(check);

#undef compare_elem

	last_id = ntohs(m_cinfo->ip->id);

	/* ret may contain UPDATE_MASTER_PACKET */
	return ret;
}

static uint32_t ipv4_compare_packet(struct compare_info *m_cinfo,
				    struct compare_info *s_cinfo)
{
	uint32_t ret = __ipv4_compare_packet(m_cinfo, s_cinfo);

	if (unlikely(ret & CHECKPOINT)) {
		same_count = 0;
		if (ret & UPDATE_COMPARE_INFO)
			ipv4_update_compare_info(m_cinfo->private_data,
						 m_cinfo->ip, m_cinfo->skb);
	} else if ((ret & SAME_PACKET) == SAME_PACKET) {
		same_count++;
	}

	if (ret & UPDATE_MASTER_PACKET) {
		BUG_ON((ret & BYPASS_MASTER) == 0);
		ipv4_update_packet(m_cinfo, s_cinfo, m_cinfo->ip->protocol,
				   ret);
	}

	return ret;
}

static void ipv4_update_compare_info(void *info, void *data,
				     struct sk_buff *skb)
{
	unsigned char protocol;
	void *ip_data;
	uint32_t len;
	struct iphdr *ip = data;
	const ipv4_compare_ops_t *ops;

	protocol = ip->protocol;
	ip_data = (char *)ip + ip->ihl * 4;
	len = ntohs(ip->tot_len) - ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->update_info)
		ops->update_info(info, ip_data, len, skb);
	rcu_read_unlock();
}

static void ipv4_flush_packets(void *info, unsigned short protocol)
{
	const ipv4_compare_ops_t *ops;

	BUG_ON(protocol >= MAX_INET_PROTOS);

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->flush_packets)
		ops->flush_packets(info);
	rcu_read_unlock();
}

uint32_t ipv4_transport_compare_fragment(struct sk_buff *m_head,
					 struct sk_buff *s_head,
					 int m_off, int s_off, int len)
{
	struct sk_buff *m_skb = ipv4_get_skb_by_offset(m_head, m_off);
	struct sk_buff *s_skb = ipv4_get_skb_by_offset(s_head, s_off);
	void *m_data, *s_data;
	int cmp_len, m_len, s_len;
	int ret;

	if (!m_skb || !s_skb)
		return CHECKPOINT | UPDATE_COMPARE_INFO;

	if (len <= 0)
		return SAME_PACKET;

	m_len = FRAG_CB(m_skb)->len - (m_off - FRAG_CB(m_skb)->offset);
	s_len = FRAG_CB(s_skb)->len - (s_off - FRAG_CB(s_skb)->offset);
	m_data = ipv4_get_data(m_skb, m_off);
	s_data = ipv4_get_data(s_skb, s_off);

#define NEXT_DATA(skb, head, data, _len, cmp_len)				\
	{									\
		if (_len > cmp_len) {						\
			FRAG_CB(skb)->len -= cmp_len;				\
			data += cmp_len;					\
		} else {							\
			skb = next_skb(skb, head);				\
			if (!skb)						\
				break;						\
			data = ipv4_get_data(skb, FRAG_CB(skb)->offset);	\
			_len = FRAG_CB(skb)->len;				\
		}								\
	}

	do {
		cmp_len = min3(m_len, s_len, len);
		ret = memcmp(m_data, s_data, cmp_len);
		if (ret)
			return CHECKPOINT | UPDATE_COMPARE_INFO;

		len -= cmp_len;
		if (len == 0)
			return SAME_PACKET;

		NEXT_DATA(m_skb, m_head, m_data, m_len, cmp_len);
		NEXT_DATA(s_skb, s_head, s_data, s_len, cmp_len);
	} while(len > 0);
#undef NEXT_DATA

	return CHECKPOINT | UPDATE_COMPARE_INFO;
}
EXPORT_SYMBOL(ipv4_transport_compare_fragment);

static uint32_t ipv4_compare_one_packet(struct compare_info *m_cinfo,
					struct compare_info *s_cinfo)
{
	struct sk_buff *skb;
	struct compare_info *cinfo = NULL;
	struct compare_info *other_cinfo = NULL;
	uint32_t ret = 0;
	const ipv4_compare_ops_t *ops;
	bool fragment;

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

	if (unlikely(cinfo->ip->ihl * 4 > cinfo->length)) {
		pr_warn("HA_compare: %s iphdr is corrupted\n",
			m_cinfo->skb ? "master" : "slave");
		goto err;
	}

	fragment = ip_is_fragment(cinfo->ip);
	cinfo->ip_data = (char *)cinfo->ip + cinfo->ip->ihl * 4;
	if (fragment)
		cinfo->length = FRAG_CB(cinfo->skb)->tot_len;
	else if (cinfo->length <= ntohs(cinfo->ip->tot_len))
		cinfo->length -= cinfo->ip->ihl * 4;
	else
		cinfo->length = ntohs(cinfo->ip->tot_len) - cinfo->ip->ihl * 4;

	/* clear other_info to avoid unexpected errors */
	other_cinfo->ip_data = NULL;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[cinfo->ip->protocol]);
	if (fragment) {
		if (ops && ops->compare_one_fragment) {
			ret = ops->compare_one_fragment(m_cinfo, s_cinfo);
		} else {
			rcu_read_unlock();
			goto unsupported;
		}
	} else {
		if (ops && ops->compare_one_packet) {
			ret = ops->compare_one_packet(m_cinfo, s_cinfo);
		} else {
			rcu_read_unlock();
			goto unsupported;
		}
	}
	rcu_read_unlock();

err:
	if (unlikely(ret & CHECKPOINT)) {
		same_count = 0;
		if (cinfo == m_cinfo && ret & UPDATE_COMPARE_INFO)
			ipv4_update_compare_info(m_cinfo->private_data,
						 m_cinfo->ip, m_cinfo->skb);
	}

	if (ret & UPDATE_MASTER_PACKET) {
		BUG_ON((ret & BYPASS_MASTER) == 0);
		BUG_ON(m_cinfo->skb == NULL);
		ipv4_update_packet(m_cinfo, s_cinfo, cinfo->ip->protocol, ret);
	}

	return ret;

unsupported:
	return 0;
}

static compare_net_ops_t ipv4_ops = {
	.compare_packets = ipv4_compare_packet,
	.compare_one_packet = ipv4_compare_one_packet,
	.flush_packets = ipv4_flush_packets,
	.update_info = ipv4_update_compare_info,
};

static int statistics_status_show(struct seq_file *m, void *data)
{
	struct ipv4_statistics *statis = m->private;

	OUTPUT_STATIS(m_error_packet);
	OUTPUT_STATIS(s_error_packet);
	OUTPUT_STATIS(ihl);
	OUTPUT_STATIS(options);
	OUTPUT_STATIS(tos);
	OUTPUT_STATIS(frag_off);
	OUTPUT_STATIS(ttl);
	OUTPUT_STATIS(id);
	OUTPUT_STATIS(data_len);
	OUTPUT_STATIS(data);
	return 0;
}

static int statistics_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, statistics_status_show, inode->i_private);
}

static const struct file_operations statistics_status_ops = {
	.open		= statistics_status_open,
	.read		= seq_read,
	.llseek		= generic_file_llseek,
	.release	= single_release,
};

static void remove_statis_file(void)
{
#define REMOVE_STATIS_FILE(entry)	REMOVE_STATIS_FILE_L(statis_entry, entry)

	REMOVE_STATIS_FILE(status_entry);
	REMOVE_STATIS_FILE(m_error_packet_entry);
	REMOVE_STATIS_FILE(s_error_packet_entry);
	REMOVE_STATIS_FILE(ihl_entry);
	REMOVE_STATIS_FILE(options_entry);
	REMOVE_STATIS_FILE(data_len_entry);
	REMOVE_STATIS_FILE(data_entry);
	REMOVE_STATIS_FILE(tos_entry);
	REMOVE_STATIS_FILE(frag_off_entry);
	REMOVE_STATIS_FILE(ttl_entry);
	REMOVE_STATIS_FILE(id_entry);
	REMOVE_STATIS_FILE(root_entry);
}

static int create_statis_file(void)
{
	int ret;

	statis_entry.root_entry = colo_create_dir("ipv4", NULL);
	CHECK_RETURN_VALUE(statis_entry.root_entry);

	statis_entry.status_entry = colo_create_file("statistics_status",
						     &statistics_status_ops,
						     statis_entry.root_entry,
						     &statis);
	CHECK_RETURN_VALUE(statis_entry.status_entry);

#define CREATE_STATIS_FILE(elem)	CREATE_STATIS_FILE_L(statis_entry.root_entry, statis, elem)
	CREATE_STATIS_FILE(m_error_packet);
	CREATE_STATIS_FILE(s_error_packet);
	CREATE_STATIS_FILE(ihl);
	CREATE_STATIS_FILE(options);
	CREATE_STATIS_FILE(data_len);
	CREATE_STATIS_FILE(data);
	CREATE_STATIS_FILE(tos);
	CREATE_STATIS_FILE(frag_off);
	CREATE_STATIS_FILE(ttl);
	CREATE_STATIS_FILE(id);

	return 0;

err:
	remove_statis_file();
	return ret;
}

static int __init compare_ipv4_init(void)
{
	int ret;

	ret = register_net_compare_ops(&ipv4_ops, COMPARE_IPV4);
	if (ret)
		return ret;

	return create_statis_file();
}

static void __exit compare_ipv4_fini(void)
{
	remove_statis_file();
	unregister_net_compare_ops(&ipv4_ops, COMPARE_IPV4);
}

module_init(compare_ipv4_init);
module_exit(compare_ipv4_fini);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
