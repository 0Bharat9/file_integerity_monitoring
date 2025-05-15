#ifndef __UNLINK_MONITOR_H
#define __UNLINK_MONITOR_H

#define FILENAME_LEN 256
#define TASK_COMM_LEN 16

struct event {
    unsigned int pid;
    unsigned int tgid;
    unsigned int uid;
    int dfd;  // Directory file descriptor
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
};

#endif // __UNLINK_MONITOR_H

