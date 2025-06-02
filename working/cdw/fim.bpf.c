#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fim.h"

// Define file access flags if not already defined
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

// Structure for tracepoint context
struct syscall_trace_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int nr;
	unsigned long args[6];
};

// Single ring buffer for all FIM events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} fim_events SEC(".maps");

// Track file descriptors opened for writing
struct fd_info {
    char pathname[BPF_PATH_MAX];
    u32 flags;
    u64 timestamp;
    bool was_written;  // Track if file was actually written to
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FD_TRACK);
    __type(key, u64);           // Combined pid + fd
    __type(value, struct fd_info);
} fd_track_map SEC(".maps");

// LRU map to track recently saved files (prevent spam)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, u64);           // Hash of pid + pathname
    __type(value, u64);         // Last event timestamp
} recent_save_map SEC(".maps");

// Temporary map for openat enter/exit coordination
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
    __type(key, u64);           // pid_tgid
    __type(value, struct temp_open_info);
} temp_open_map SEC(".maps");

// Helper function to create the key from pid and fd
static __always_inline u64 gen_pid_fd_key(u32 pid, int fd)
{
    return ((u64)pid << 32) | (u32)fd;
}

// Simple string hash for deduplication
static __always_inline u64 hash_string(const char *str, int max_len)
{
    u64 hash = 5381;
    for (int i = 0; i < max_len && str[i]; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }
    return hash;
}

// Check if we should skip this event (rate limiting)
static __always_inline bool should_skip_event(u32 pid, const char *pathname)
{
    u64 hash_key = ((u64)pid << 32) | (hash_string(pathname, BPF_PATH_MAX) & 0xFFFFFFFF);
    u64 now = bpf_ktime_get_ns();
    u64 *last_time = bpf_map_lookup_elem(&recent_save_map, &hash_key);
    
    // Skip if event happened within last 1 second for same file
    if (last_time && (now - *last_time) < 1000000000ULL) {
        return true;
    }
    
    // Update timestamp
    bpf_map_update_elem(&recent_save_map, &hash_key, &now, BPF_ANY);
    return false;
}

// Helper function to send FIM event
static inline int send_fim_event(void *ctx, __u32 event_type, __u32 pid, __u32 tgid, 
                                __u32 uid, const char *filename, int dirfd, 
                                int flags, __u32 mode, const char *comm) {
    struct fim_event *event;
    
    event = bpf_ringbuf_reserve(&fim_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = pid;
    event->tgid = tgid;
    event->uid = uid;
    event->event_type = event_type;
    event->flags = flags;
    event->mode = mode;
    event->dirfd = dirfd;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_probe_read_str(&event->comm, sizeof(event->comm), comm);
    bpf_probe_read_str(&event->filename, sizeof(event->filename), filename);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ===== FILE CREATION AND TRACKING =====

// Store path information when file is opened
SEC("tp/syscalls/sys_enter_openat")
int trace_enter_openat(struct syscall_trace_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int dfd = (int)ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    int flags = ctx->args[2];
    u32 mode = ctx->args[3];
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char comm[TASK_COMM_LEN];
    
    // Get process name
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Store temporary info for the exit handler
    struct temp_open_info temp_info = {};
    temp_info.flags = flags;
    temp_info.mode = mode;
    temp_info.dirfd = dfd;
    temp_info.timestamp = bpf_ktime_get_ns();
    
    // Try to read the filename
    if (filename) {
        bpf_probe_read_user_str(temp_info.pathname, sizeof(temp_info.pathname), filename);
    }
    
    // Store temporary info
    bpf_map_update_elem(&temp_open_map, &id, &temp_info, BPF_ANY);
    
    // Check if O_CREAT flag is set - send CREATE event immediately
    if (flags & O_CREAT) {
        send_fim_event(ctx, EVENT_TYPE_CREATE, pid, tgid, uid, temp_info.pathname, 
                      dfd, flags, mode, comm);
    }
    
    return 0;
}

// Store fd -> path mapping when open returns successfully
SEC("tp/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->ret;
    
    // Look up the temporary entry
    struct temp_open_info *temp_info = bpf_map_lookup_elem(&temp_open_map, &id);
    if (!temp_info) {
        return 0;
    }
    
    // Clean up temporary entry first
    bpf_map_delete_elem(&temp_open_map, &id);
    
    // Skip if open failed
    if (fd < 0) {
        return 0;
    }
    
    // Only track files opened for writing or that could be modified
    if (!(temp_info->flags & O_WRONLY) && !(temp_info->flags & O_RDWR) && 
        !(temp_info->flags & O_CREAT) && !(temp_info->flags & O_TRUNC)) {
        return 0;
    }
    
    // Store fd tracking info
    struct fd_info info = {};
    info.flags = temp_info->flags;
    info.timestamp = temp_info->timestamp;
    info.was_written = false;  // Initialize as not written
    __builtin_memcpy(info.pathname, temp_info->pathname, BPF_PATH_MAX);
    
    // Store with the proper key (pid + fd)
    u64 key = gen_pid_fd_key(pid, fd);
    bpf_map_update_elem(&fd_track_map, &key, &info, BPF_ANY);
    
    return 0;
}

// ===== TRACK WRITE OPERATIONS (to know if file was modified) =====

// Track any write operation to mark file as modified
SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    
    // Mark this fd as having been written to
    u64 key = gen_pid_fd_key(pid, fd);
    struct fd_info *info = bpf_map_lookup_elem(&fd_track_map, &key);
    if (info) {
        info->was_written = true;
        bpf_map_update_elem(&fd_track_map, &key, info, BPF_EXIST);
    }
    
    return 0;
}

// Track pwrite operations
SEC("tp/syscalls/sys_enter_pwrite64")
int trace_pwrite_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    
    u64 key = gen_pid_fd_key(pid, fd);
    struct fd_info *info = bpf_map_lookup_elem(&fd_track_map, &key);
    if (info) {
        info->was_written = true;
        bpf_map_update_elem(&fd_track_map, &key, info, BPF_EXIST);
    }
    
    return 0;
}

// Track writev operations
SEC("tp/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    
    u64 key = gen_pid_fd_key(pid, fd);
    struct fd_info *info = bpf_map_lookup_elem(&fd_track_map, &key);
    if (info) {
        info->was_written = true;
        bpf_map_update_elem(&fd_track_map, &key, info, BPF_EXIST);
    }
    
    return 0;
}

// ===== FILE SAVE DETECTION =====

// Monitor fsync - indicates file save
SEC("tp/syscalls/sys_enter_fsync")
int trace_fsync_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int fd = ctx->args[0];
    char comm[TASK_COMM_LEN];
    
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if we're tracking this fd
    u64 key = gen_pid_fd_key(pid, fd);
    struct fd_info *info = bpf_map_lookup_elem(&fd_track_map, &key);
    if (!info || !info->was_written)
        return 0;
    
    // Rate limiting check
    if (should_skip_event(pid, info->pathname)) {
        return 0;
    }
    
    return send_fim_event(ctx, EVENT_TYPE_SAVE, pid, tgid, uid, info->pathname, 
                         -1, 0, 0, comm);
}

// Monitor fdatasync - also indicates file save
SEC("tp/syscalls/sys_enter_fdatasync")
int trace_fdatasync_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int fd = ctx->args[0];
    char comm[TASK_COMM_LEN];
    
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if we're tracking this fd
    u64 key = gen_pid_fd_key(pid, fd);
    struct fd_info *info = bpf_map_lookup_elem(&fd_track_map, &key);
    if (!info || !info->was_written)
        return 0;
    
    // Rate limiting check
    if (should_skip_event(pid, info->pathname)) {
        return 0;
    }
    
    return send_fim_event(ctx, EVENT_TYPE_SAVE, pid, tgid, uid, info->pathname, 
                         -1, 0, 0, comm);
}

// Monitor close operations - many programs save on close
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
    
    // Only generate SAVE event if file was actually written to
    if (info && info->was_written) {
        // Rate limiting check
        if (!should_skip_event(pid, info->pathname)) {
            send_fim_event(ctx, EVENT_TYPE_SAVE, pid, tgid, uid, info->pathname, 
                          -1, 0, 0, comm);
        }
    }
    
    // Always cleanup the fd tracking
    bpf_map_delete_elem(&fd_track_map, &key);
    
    return 0;
}

// ===== FILE DELETION MONITORING =====

// Trace file deletion events via do_unlinkat
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    const char *fname;
    __u64 id;
    __u32 tgid, pid, uid;
    char comm[TASK_COMM_LEN];
    
    // Get process information
    id = bpf_get_current_pid_tgid();
    tgid = (__u32)(id >> 32);
    pid = (__u32)id;
    uid = (__u32)bpf_get_current_uid_gid();
    
    // Get process name
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Extract filename using BPF_CORE_READ
    fname = BPF_CORE_READ(name, name);
    if (!fname)
        return 0;
    
    // Send delete event
    send_fim_event(ctx, EVENT_TYPE_DELETE, pid, tgid, uid, fname, dfd, 0, 0, comm);
    
    return 0;
}

// ===== CLEANUP OPERATIONS =====

// Cleanup on dup2 operations (fd reassignment)
SEC("tp/syscalls/sys_enter_dup2")
int trace_dup2_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int newfd = ctx->args[1];
    
    // Clean up the target fd if it was being tracked
    u64 key = gen_pid_fd_key(pid, newfd);
    bpf_map_delete_elem(&fd_track_map, &key);
    
    return 0;
}

// Cleanup on dup3 operations (fd reassignment with flags)
SEC("tp/syscalls/sys_enter_dup3")
int trace_dup3_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int newfd = ctx->args[1];
    
    // Clean up the target fd if it was being tracked
    u64 key = gen_pid_fd_key(pid, newfd);
    bpf_map_delete_elem(&fd_track_map, &key);
    
    return 0;
}

char _license[] SEC("license") = "GPL";
