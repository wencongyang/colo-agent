/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#ifndef COMPARE_H
#define COMPARE_H

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

struct compare_info {
	struct sk_buff *skb;
	struct ethhdr *eth;
	union {
		void *packet;
		struct iphdr *ip;
		struct arphdr *arp;
	};
	union {
		void *ip_data;
		struct tcphdr *tcp;
		struct udphdr *udp;
	};
	union {
		void *transport_data;
		void *tcp_data;
		void *udp_data;
	};
	unsigned int length;

	/* length: 32*4 bytes */
	void *private_data;
};

#define		BYPASS_MASTER		0x01
#define		DROP_SLAVER		0x02
#define		SAME_PACKET		(BYPASS_MASTER | DROP_SLAVER)
#define		CHECKPOINT		0x80000000
#define		UPDATE_COMPARE_INFO	0x40000000
#define		UPDATE_MASTER_PACKET	0x20000000
#define		IGNORE_LEN		0x10000000
#define		CLONED_PACKET		0x8000000

extern uint32_t default_compare_data(void *m_data, void *s_data, int length);

/*
 * for network layer protocol. Currently, we only support:
 *   arp
 *   ipv4
 *   ipv6(TODO)
 *
 * It is protected by RCU, so don't sleep in all callbacks
 */
typedef struct compare_net_ops {
	uint32_t (*compare_packets)(struct compare_info *m_cinfo,
				    struct compare_info *s_cinfo);
	uint32_t (*compare_one_packet)(struct compare_info *m_cinfo,
				       struct compare_info *s_cinfo);

	/*
	 * info: compare_info.private_data
	 * data: compare_info.packet
	 * protocol: transport layer protocol, network endian
	 */
	void (*update_info)(void *info, void *data, struct sk_buff *skb);
	void (*flush_packets)(void *info, unsigned short protocol);
} compare_net_ops_t;

enum compare_net_protocol{
	COMPARE_IPV4,
	COMPARE_ARP,
	COMPARE_IPV6,

	COMPARE_LAST,
};

extern int register_net_compare_ops(const compare_net_ops_t *ops,
				    unsigned char protocol);
extern int unregister_net_compare_ops(const compare_net_ops_t *ops,
				      unsigned char protocol);

/* caller should hold rcu_lock()
 * protocol: network layer's protocol, network endian
 */
extern const compare_net_ops_t *get_compare_net_ops(unsigned short protocol);

#endif
