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

#ifndef COMPARE_DEBUGFS_H
#define COMPARE_DEBUGFS_H

extern const struct file_operations colo_u64_ops;

extern int __init colo_debugfs_init(void);
extern void __exit colo_debugfs_fini(void);

/* use IS_ERR_OR_NULL to check the return value */
extern struct dentry * colo_create_file(const char *name,
					const struct file_operations *fops,
					struct dentry *parent,
					void *data);
extern void colo_remove_file(struct dentry *entry);

/* use IS_ERR_OR_NULL to check the return value */
extern struct dentry * colo_create_dir(const char *name,
				       struct dentry *parent);

extern struct dentry *colo_add_status_file(const char *name,
					   struct vm_connections *vmcs);

#define CREATE_STATIS_FILE_L(parent, statis, elem)			\
	do {								\
		struct dentry *entry;					\
		void *data = &statis.elem;				\
		entry = colo_create_file(#elem, &colo_u64_ops,		\
					 parent, data);			\
		CHECK_RETURN_VALUE(entry);				\
		statis##_entry.elem##_entry = entry;			\
	} while (0)

#define CHECK_RETURN_VALUE(entry)		\
	do {					\
		if (!entry) {			\
			ret = -ENOMEM;		\
			goto err;		\
		} else if (IS_ERR(entry)) {	\
			ret = PTR_ERR(entry);	\
			goto err;		\
		}				\
	} while (0)

#define REMOVE_STATIS_FILE_L(statis, entry)			\
	do {							\
		if (statis.entry) {				\
			colo_remove_file(statis.entry);		\
			statis.entry = NULL;			\
		}						\
	} while (0)

#define OUTPUT_STATIS(elem)						\
	do {								\
		if (strlen(#elem) < 7)					\
			seq_printf(m, #elem":\t\t%lld\n", statis->elem);\
		else							\
			seq_printf(m, #elem":\t%lld\n", statis->elem);	\
	} while (0)

#endif
