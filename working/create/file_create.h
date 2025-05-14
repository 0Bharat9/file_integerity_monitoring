/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILE_CREATE_H
#define __FILE_CREATE_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

struct create_event {
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	int flags;
	__u32 mode;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

#endif /* __FILE_CREATE_H */

