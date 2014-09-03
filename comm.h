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

#ifndef COLO_COMM_H
#define COLO_COMM_H

#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <net/pkt_sched.h>

#include "connections.h"
#include "ip_fragment.h"

struct colo_sched_data {
	struct if_connections *ics; /* packets not compared */
	struct sk_buff_head rel; /* packest compared successfully */
	struct Qdisc* sch;
	uint32_t flags;

	struct ip_frags ipv4_frags;
};

#endif
