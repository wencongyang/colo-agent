/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Manage the connections
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#ifndef COLO_CONNECTIONS_H
#define COLO_CONNECTIONS_H

#include <linux/skbuff.h>
#include <linux/types.h>

#define HASH_NR 	10000

#define IS_MASTER	(1 << 0)
#define DESTROY		(1 << 16)

struct colo_idx {
	uint32_t master_idx;
	uint32_t slave_idx;
};

struct connection_keys {
	/* (src,dst) must be grouped, in the same way than in IP header */
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	u16 thoff;
	u8 ip_proto;
};

struct if_connections;
struct colo_sched_data;

struct connect_info {
	struct sk_buff_head master_queue;
	struct sk_buff_head slave_queue;
	struct if_connections *ics;

	struct connection_keys key;
	struct list_head list;
	struct list_head compare_list;
	uint32_t state;
	wait_queue_head_t wait;
	uint64_t touch_time;
	int flushed :1;

	/* transport layer defines it */
	uint32_t m_info[32];
	uint32_t s_info[32];
};

/* state */
#define IN_COMPARE	(1 << 0)
#define IN_DESTROY	(1 << 1)

/*
 * one vm can have more than one nic, all nic's connections is
 * managed by vm_connections.
 */
struct vm_connections {
	/* point to the next vm or list head */
	struct list_head vm_entry;
	/* head of all ics's list */
	struct list_head vm_ics;
	int vm_idx;
	/* protect vm_ics and compare_data */
	spinlock_t lock;
	void *compare_data;

	/* This lock may be hold in softirq context */
	spinlock_t compare_lock;
	struct list_head compare_head;

	/*
	 * compare thread will wait on this queue if no more packets
	 * to be compared.
	 */
	wait_queue_head_t compare_queue;
	wait_queue_head_t checkpoint_queue;

	struct kref ref;
};

/* manage one nic's connections */
struct if_connections {
	struct list_head entry[HASH_NR];
	struct colo_idx idx;
	struct sk_buff_head wait_for_release;
	struct colo_sched_data *master_data;
	struct colo_sched_data *slave_data;
	struct list_head list;
	struct vm_connections *vmcs;
	int master:1, slave:1;
};

extern struct connect_info *insert(struct if_connections *ics,
				   struct sk_buff *skb,
				   uint32_t flags);
extern struct if_connections *alloc_if_connections(struct colo_idx *idx,
						   int flags,
						   int vm_idx);
extern void free_if_connections(struct if_connections *ics, int flags);
extern void connections_init(void);
extern struct vm_connections *get_vm_connections(int vm_idx);
extern void put_vm_connections(struct vm_connections *vmcs);

#endif
