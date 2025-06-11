#ifndef FIM_USERSPACE_H
#define FIM_USERSPACE_H

// Userspace headers - safe to include standard library
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <openssl/evp.h>
#include <openssl/md5.h> 
// Include the generated skeleton
#include "fim.skel.h"

// Constants
#define MAX_EXCLUDE_PATTERNS    64
#define MAX_WATCH_PATTERNS      64
#define AT_FDCWD               -100
#define MAX_FILE_CACHE         1000
#define HASH_SIZE              16
#define LOG_FILE_PATH          "/var/log/fim.log"
#define PATH_MAX               4096

// Event types (should match BPF program)
#define EVENT_TYPE_CREATE      1
#define EVENT_TYPE_DELETE      2
#define EVENT_TYPE_SAVE        3
#define EVENT_TYPE_RENAME      4
#define EVENT_TYPE_SYMLINK     5
#define EVENT_TYPE_TIMESTAMP   6
#define EVENT_TYPE_CHOWN       7
#define EVENT_TYPE_CHMOD       8

// Global environment configuration
struct env {
    bool verbose;
    bool timestamp;
    bool print_uid;
    bool exclude_dev_null;
    bool exclude_tmp_files;
    bool exclude_editor_noise;
    bool strict_watch;
    bool monitor_create;
    bool monitor_delete;
    bool monitor_write;
    bool monitor_rename;
    bool monitor_symlink;
    bool monitor_time_change;
    bool monitor_chown;
    bool monitor_chmod;
    bool show_flags;
    bool content_aware;
    bool ignore_unchanged;
    bool enable_logging;
    char *name_filter;
    char *exclude_patterns[MAX_EXCLUDE_PATTERNS];
    int exclude_pattern_count;
    char *watch_patterns[MAX_WATCH_PATTERNS];
    int watch_pattern_count;
    __u32 pid;
    __u32 uid;
};

extern struct env env;
extern struct file_state *file_cache[MAX_FILE_CACHE];
extern int cache_entries;
extern FILE *log_file;
extern struct passwd *pw;
extern volatile sig_atomic_t exiting;
extern int stats_fd;

// BPF event structure (should match BPF program)
struct fim_event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 event_type;
    int flags;
    __u32 mode;
    int dirfd;
    __u64 timestamp;
    char comm[16];
    char filename[256];
};

#endif /* FIM_USERSPACE_H */
