#ifndef __FILE_CREATE_H
#define __FILE_CREATE_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define PATH_MAX 4096
#define INVALID_UID ((uid_t)-1)

struct create_event {
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	int flags;
	__u32 mode;
	int dirfd;  // Directory file descriptor for openat
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

#endif /* __FILE_CREATE_H */

