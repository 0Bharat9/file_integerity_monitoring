#ifndef BPF_FIM_H
#define BPF_FIM_H

// eBPF-specific header - only include kernel definitions
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Constants (matching userspace)
#define MAX_EXCLUDE_PATTERNS    64
#define MAX_WATCH_PATTERNS      64
#define AT_FDCWD               -100
#define MAX_FILE_CACHE         1000
#define HASH_SIZE              16

// Event types (should match userspace program)
#define EVENT_TYPE_CREATE      1
#define EVENT_TYPE_DELETE      2
#define EVENT_TYPE_SAVE        3
#define EVENT_TYPE_RENAME      4
#define EVENT_TYPE_SYMLINK     5
#define EVENT_TYPE_TIMESTAMP   6
#define EVENT_TYPE_CHOWN       7
#define EVENT_TYPE_CHMOD       8

#define BPF_PATH_MAX 256
#define TASK_COMM_LEN 16
#define FILENAME_LEN 256
// BPF event structure (should match userspace)

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
    char old_filename[BPF_PATH_MAX];  // For rename operations
    char target_path[BPF_PATH_MAX];   // For symlink targets
};


#endif /* BPF_FIM_H */
