#ifndef FILE_MODIFY_H
#define FILE_MODIFY_H

#define PATH_MAX 4096
#define TASK_COMM_LEN 16

struct modify_event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    int fd;
    off_t offset;
    size_t count;
    char comm[TASK_COMM_LEN];
    char pathname[PATH_MAX];
};

#endif /* FILE_MODIFY_H */

