#ifndef __UNLINK_MONITOR_H
#define __UNLINK_MONITOR_H

#define FILENAME_LEN 256

struct event {
    unsigned int pid;
    char filename[FILENAME_LEN];
};

#endif // __UNLINK_MONITOR_H

