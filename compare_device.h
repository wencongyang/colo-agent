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

#ifndef COMPARE_DEVICE_H
#define COMPARE_DEVICE_H

enum {
	state_comparing,
	state_incheckpoint,
};
extern uint32_t state;

extern int colo_dev_init(void);
extern void colo_dev_fini(void);
extern int compare_kthread(void *);

#endif
