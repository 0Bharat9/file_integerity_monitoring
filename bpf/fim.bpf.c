#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_fim.h"

// File access flags
#ifndef O_CREAT
#define O_CREAT		00000100
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif

#define MAX_FD_TRACK 4096

// Stat counters for monitoring
#define STAT_DROPPED_EVENTS 0
#define STAT_TOTAL_EVENTS   1
#define STAT_CREATE_EVENTS  2
#define STAT_SAVE_EVENTS    3
#define STAT_DELETE_EVENTS  4
#define STAT_RENAME_EVENTS    5
#define STAT_SYMLINK_EVENTS   6
#define STAT_TIMESTAMP_EVENTS 7
#define STAT_CHOWN_EVENTS     8
#define STAT_CHMOD_EVENTS     9

//syscall tracepoint structure
struct ebpf_syscall_trace_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int nr;
	unsigned long args[6];
};

// Main ring buffer for all FIM events - 64MB
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<24);
} fim_events SEC(".maps");

// Track for open file descriptors that might be modified
struct fd_info {
    char pathname[BPF_PATH_MAX];
    u32 flags;
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FD_TRACK);
    __type(key, u64);  // pid << 32 | fd
    __type(value, struct fd_info);
} fd_track_map SEC(".maps");

// Temporary storage for openat syscall coordination between enter/exit
struct temp_open_info {
    char pathname[BPF_PATH_MAX];
    u32 flags;
    u32 mode;
    int dirfd;
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // pid_tgid
    __type(value, struct temp_open_info);
} temp_open_map SEC(".maps");

// Event statistics tracking
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u64);
} stats_map SEC(".maps");

// Create unique key for process + file descriptor combo
static __always_inline u64 gen_pid_fd_key(u32 pid, int fd)
{
    return ((u64)pid << 32) | (u32)fd;
}

// Check if we should ignore this path (common temp/system directories)
static __always_inline bool should_exclude_path(const char *pathname) {
    if (!pathname)
        return true;
    // Core kernel/system pseudo-filesystems
    if (bpf_strncmp(pathname, 6, "/proc/") == 0 ||
        bpf_strncmp(pathname, 5, "/sys/") == 0 ||
        bpf_strncmp(pathname, 5, "/dev/") == 0 ||
        bpf_strncmp(pathname, 5, "/run/") == 0) {
        return true;
    }
    //system directories to ignore
    if (bpf_strncmp(pathname, 13, "/sys/kernel/") == 0 ||
        bpf_strncmp(pathname, 12, "/proc/self/") == 0 ||
        bpf_strncmp(pathname, 11, "/dev/shm/") == 0 ||
        bpf_strncmp(pathname, 10, "/sys/fs/") == 0 ||
        bpf_strncmp(pathname, 15, "/sys/devices/") == 0) {
        return true;
    }
    // Container/virtualization pseudo-filesystems
    if (bpf_strncmp(pathname, 13, "/sys/fs/cgroup") == 0 ||
        bpf_strncmp(pathname, 12, "/proc/sys/") == 0) {
        return true;
    }
    // Highly noisy application directories (consider case-by-case)
    if (bpf_strncmp(pathname, 14, "/var/cache/") == 0 ||
        bpf_strncmp(pathname, 13, "/var/spool/") == 0 ||
        bpf_strncmp(pathname, 11, "/var/tmp/") == 0) {
        return true;
    }
    return false;
}

// Send a FIM event to userspace
static inline int send_fim_event(void *ctx, __u32 event_type, __u32 pid, __u32 tgid, 
                                __u32 uid, const char *filename, int dirfd, 
                                int flags, __u32 mode, const char *comm) {
    
    struct fim_event *event;
    
    // Update total events counter
    u32 total_key = STAT_TOTAL_EVENTS;
    u64 *total_val = bpf_map_lookup_elem(&stats_map, &total_key);
    if (total_val) {
        (*total_val)++;
        bpf_map_update_elem(&stats_map, &total_key, total_val, BPF_EXIST);
    }
    
    // Update counter for this specific event type
    u32 type_key;
    switch (event_type) {
        case EVENT_TYPE_CREATE: type_key = STAT_CREATE_EVENTS; break;
        case EVENT_TYPE_DELETE: type_key = STAT_DELETE_EVENTS; break;
        case EVENT_TYPE_SAVE: type_key = STAT_SAVE_EVENTS; break;
        case EVENT_TYPE_RENAME: type_key = STAT_RENAME_EVENTS; break;
        case EVENT_TYPE_SYMLINK: type_key = STAT_SYMLINK_EVENTS; break;
        case EVENT_TYPE_TIMESTAMP: type_key = STAT_TIMESTAMP_EVENTS; break;
        case EVENT_TYPE_CHOWN: type_key = STAT_CHOWN_EVENTS; break;
        default: type_key = STAT_CHMOD_EVENTS; break;
    }
    
    u64 *type_val = bpf_map_lookup_elem(&stats_map, &type_key);
    if (type_val) {
        (*type_val)++;
        bpf_map_update_elem(&stats_map, &type_key, type_val, BPF_EXIST);
    }
    
    // Try to reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&fim_events, sizeof(*event), 0);
    if (!event) {
        // Track dropped events when ring buffer is full
        u32 dropped_key = STAT_DROPPED_EVENTS;
        u64 *dropped_val = bpf_map_lookup_elem(&stats_map, &dropped_key);
        if (dropped_val) {
            (*dropped_val)++;
            bpf_map_update_elem(&stats_map, &dropped_key, dropped_val, BPF_EXIST);
        }
        return 0;
    }
    
    // event details
    event->pid = pid;
    event->tgid = tgid;
    event->uid = uid;
    event->event_type = event_type;
    event->flags = flags;
    event->mode = mode;
    event->dirfd = dirfd;
    event->timestamp = bpf_ktime_get_ns();
    
    // Copy process name and filename - discard event if copy fails
    if (bpf_probe_read_str(&event->comm, sizeof(event->comm), comm) < 0 || 
        bpf_probe_read_str(&event->filename, sizeof(event->filename), filename) < 0) {
        bpf_ringbuf_discard(event, 0);
        return -1;
    }
 
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// === FILE CREATION AND MODIFICATION TRACKING ===
// Capture file open attempts - store info for the exit handler
SEC("tp/syscalls/sys_enter_openat")
int trace_enter_openat(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    int dfd = (int)ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    int flags = ctx->args[2];
    u32 mode = ctx->args[3];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Store temporary info for coordination with exit handler
    struct temp_open_info temp_info = {};
    temp_info.flags = flags;
    temp_info.mode = mode;
    temp_info.dirfd = dfd;
    temp_info.timestamp = bpf_ktime_get_ns();
    
    if (filename) {
        bpf_probe_read_user_str(temp_info.pathname, sizeof(temp_info.pathname), filename);
        if (should_exclude_path(temp_info.pathname)) {
            return 0;
        }
    }
    
    bpf_map_update_elem(&temp_open_map, &id, &temp_info, BPF_ANY);
    
    // If creating a new file, send CREATE event immediately
    if (flags & O_CREAT) {
        send_fim_event(ctx, EVENT_TYPE_CREATE, pid, tgid, uid, temp_info.pathname, 
                      dfd, flags, mode, comm);
    }
    
    return 0;
}

// Handling successful file opens - set up tracking for modification check
SEC("tp/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->ret;
    
    struct temp_open_info *temp_info = bpf_map_lookup_elem(&temp_open_map, &id);
    if (!temp_info) {
        return 0;
    }
    
    // Clean up temporary storage
    bpf_map_delete_elem(&temp_open_map, &id);
    
    // Skip failed opens
    if (fd < 0) {
        return 0;
    }
    
    // Only tracking files that are modified
    if (!(temp_info->flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))) {
        return 0;
    }
    
    // Setting up tracking for file descriptor
    struct fd_info info = {};
    info.flags = temp_info->flags;
    info.timestamp = temp_info->timestamp;
    __builtin_memcpy(info.pathname, temp_info->pathname, BPF_PATH_MAX);
    
    u64 key = gen_pid_fd_key(pid, fd);
    bpf_map_update_elem(&fd_track_map, &key, &info, BPF_ANY);
    
    return 0;
}

// Detecting file modifications only when applications close file descriptors
SEC("tp/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int fd = ctx->args[0];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    u64 key = gen_pid_fd_key(pid, fd);
    struct fd_info *info = bpf_map_lookup_elem(&fd_track_map, &key);
    
    if (info && !should_exclude_path(info->pathname)) {
        send_fim_event(ctx, EVENT_TYPE_SAVE, pid, tgid, uid, info->pathname, 
                      -1, 0, 0, comm);
    }
    
    bpf_map_delete_elem(&fd_track_map, &key);
    
    return 0;
}

// === FILE DELETION MONITORING ===
// Monitoring file deletions using unlink handler
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Extracting the filename from kernel structure
    const char *fname = BPF_CORE_READ(name, name);
    if (!fname)
        return 0;
    
    char pathname[256];
    bpf_probe_read_kernel_str(pathname, sizeof(pathname), fname);
    
    if (should_exclude_path(pathname)) {
        return 0;
    }
    
    send_fim_event(ctx, EVENT_TYPE_DELETE, pid, tgid, uid, fname, dfd, 0, 0, comm);
    
    return 0;
}

// === FILE METADATA CHANGES ===
// NOTE: timestamp change detection are not working rn.

// Detecting timestamp change attempts
SEC("tp/syscalls/sys_enter_utimensat")
int trace_utimensat_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    int dirfd = (int)ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    char pathname[256];
    bpf_probe_read_kernel_str(pathname, sizeof(pathname), filename);
    
    if (should_exclude_path(pathname)) {
        return 0;
    }
   
    send_fim_event(ctx, EVENT_TYPE_TIMESTAMP, pid, tgid, uid, filename, 
                  dirfd, 0, 0, comm);
    return 0;
}

// Tracking file renames and moves
// FIXME: BPF param limit prevents passing both rename paths (old+new names)
// NOTE: BPF param constraints - full params: compiler error | reduced params: runtime validation failure

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    int olddirfd = (int)ctx->args[0];
    const char *oldpath = (const char *)ctx->args[1];
    unsigned int flags = (unsigned int)ctx->args[4];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    char pathname[256];
    bpf_probe_read_kernel_str(pathname, sizeof(pathname), oldpath);
    
    if (should_exclude_path(pathname)) {
        return 0;
    }
    
    send_fim_event(ctx, EVENT_TYPE_RENAME, pid, tgid, uid, oldpath, 
                  olddirfd, flags, 0, comm);
    return 0;
}

// Handling legacy rename syscall
SEC("tp/syscalls/sys_enter_rename")
int trace_rename_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    const char *oldpath = (const char *)ctx->args[0];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    char pathname[256];
    bpf_probe_read_kernel_str(pathname, sizeof(pathname), oldpath);
    
    if (should_exclude_path(pathname)) {
        return 0;
    }

    send_fim_event(ctx, EVENT_TYPE_RENAME, pid, tgid, uid, oldpath, 
                  -1, 0, 0, comm);
    return 0;
}

// === SYMLINK CREATION TRACKING ===
// FIXME: BPF param limit prevents passing both symlink paths (old+new names)
// NOTE: BPF param constraints - full params: compiler error | reduced params: runtime validation failure

// Monitoring symlink creation
SEC("tp/syscalls/sys_enter_symlink")
int trace_symlink_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    const char *linkpath = (const char *)ctx->args[1];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    char pathname[256];
    bpf_probe_read_kernel_str(pathname, sizeof(pathname), linkpath);
    
    if (should_exclude_path(pathname)) {
        return 0;
    }

    send_fim_event(ctx, EVENT_TYPE_SYMLINK, pid, tgid, uid, linkpath, 
                  -1, 0, 0, comm);
    return 0;
}

// Monitoring symlink creation with dirfd
SEC("tp/syscalls/sys_enter_symlinkat")
int trace_symlinkat_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    int newdirfd = (int)ctx->args[1];
    const char *linkpath = (const char *)ctx->args[2];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    char pathname[256];
    bpf_probe_read_kernel_str(pathname, sizeof(pathname), linkpath);
    
    if (should_exclude_path(pathname)) {
        return 0;
    }
    
    send_fim_event(ctx, EVENT_TYPE_SYMLINK, pid, tgid, uid, linkpath, 
                  newdirfd, 0, 0, comm);
    return 0;
}

// === PERMISSION CHANGES ===
// Track ownership changes
SEC("tp/syscalls/sys_enter_fchownat")
int trace_chown_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    int dirfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    uid_t owner = (uid_t)ctx->args[2];
    gid_t group = (gid_t)ctx->args[3];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    send_fim_event(ctx, EVENT_TYPE_CHOWN, pid, tgid, uid, pathname, 
                  dirfd, owner, group, comm);
    return 0;
}

// Track permission changes
SEC("tp/syscalls/sys_enter_fchmodat")
int trace_chmod_enter(struct ebpf_syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    int dirfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    umode_t mode = (umode_t)ctx->args[2];
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    send_fim_event(ctx, EVENT_TYPE_CHMOD, pid, tgid, uid, pathname, 
                  dirfd, 0, mode, comm);
    return 0;
}

char _license[] SEC("license") = "GPL";

