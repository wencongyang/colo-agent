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

#ifndef COMPARE_IPV4_H
#define COMPARE_IPV4_H

/* It is protected by RCU, so don't sleep in all callbacks */
typedef struct ipv4_compare_ops {
	uint32_t (*compare)(struct compare_info *m_cinfo,
			    struct compare_info *s_cinfo);
	uint32_t (*compare_one_packet)(struct compare_info *m_cinfo,
				       struct compare_info *s_cinfo);
	uint32_t (*compare_fragment)(struct compare_info *m_cinfo,
				     struct compare_info *s_cinfo);
	uint32_t (*compare_one_fragment)(struct compare_info *m_cinfo,
					 struct compare_info *s_cinfo);
	void (*update_info)(void *info, void *data, uint32_t len, struct sk_buff *skb);
	void (*update_packet)(struct compare_info *m_cinfo,
			      struct compare_info *s_cinfo,
			      uint32_t ret);
	void (*flush_packets)(void *info);
	void (*debug_print)(const struct compare_info *cinfo, const void *data,
			    int length);
} ipv4_compare_ops_t;

extern int register_ipv4_compare_ops(ipv4_compare_ops_t *ops,
				     unsigned short protocol);
extern int unregister_ipv4_compare_ops(ipv4_compare_ops_t *ops,
				       unsigned short protocol);
extern uint32_t ipv4_transport_compare_fragment(struct sk_buff *m_head,
						struct sk_buff *s_head,
						int m_off, int s_off, int len);

#endif
