#ifndef __COMMON_H
#define __COMMON_H

#define FILENAME_LEN 256

struct event {
    int pid;
    int dirfd;
    char filename[FILENAME_LEN];
    __u64 flags;
};

#endif

