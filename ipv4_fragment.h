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

#ifndef IPV4_FRAGMENT_H
#define IPV4_FRAGMENT_H

extern void ipv4_frags_init(void);
extern struct sk_buff *ipv4_defrag(struct sk_buff *skb, struct ip_frags *ip_frags);
/* head: the fragment 0 of the ipv4 fragments */
extern struct sk_buff *ipv4_get_skb_by_offset(struct sk_buff *head, int offset);
/* offset: this offset shoule be in the skb */
extern void *ipv4_get_data(struct sk_buff *skb, int offset);
extern int ipv4_copy_transport_head(void *data, struct sk_buff *head, int size);
extern void copy_ipv4_frags(struct ip_frags *src_ip_frags,
			    struct ip_frags *dst_ip_frags);
extern void clear_ipv4_frags(struct ip_frags *ip_frags);

#endif
