#ifndef __FIM_H
#define __FIM_H

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256
#define PATH_MAX 4096
#define BPF_PATH_MAX 256
#define COMM_MAX 16

// Event types
#define EVENT_TYPE_CREATE 1
#define EVENT_TYPE_DELETE 2
#define EVENT_TYPE_SAVE   3

// Single FIM event structure for all events
struct fim_event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 event_type;  // CREATE, DELETE, or SAVE
    int flags;         // For create events (openat flags)
    __u32 mode;        // For create events (file mode)
    int dirfd;         // Directory file descriptor
    __u64 timestamp;   // Event timestamp (nanoseconds)
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
};

#endif /* __FIM_H */
