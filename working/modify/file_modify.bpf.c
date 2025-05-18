#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "file_modify.h"

// Define file access flags if not already defined
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif

// Use a reasonable size that won't exceed BPF stack limits
#define BPF_PATH_MAX 256

// Maps to collect event data
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} modify_events SEC(".maps");

// Helper hash map to track FDs to their paths
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);       // Combined pid + fd
    __type(value, bool);    // Just mark it as tracked, path resolution in userspace
} fd_track_map SEC(".maps");

// Helper function to create the key from pid and fd
static __always_inline u64 gen_pid_fd_key(u32 pid, int fd)
{
    return ((u64)pid << 32) | (u32)fd;
}

// Store path information when file is opened
SEC("tp/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int dfd = ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    int flags = ctx->args[2];
    
    // Only track files opened for writing
    if (!(flags & O_WRONLY) && !(flags & O_RDWR))
        return 0;
    
    // We'll get the fd in the return probe
    return 0;
}

// Store fd -> path mapping when open returns
SEC("tp/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->ret;
    
    // Skip if open failed
    if (fd < 0)
        return 0;
    
    // Just store the fd as tracked, we'll resolve path in userspace
    u64 key = gen_pid_fd_key(pid, fd);
    bool tracked = true;
    bpf_map_update_elem(&fd_track_map, &key, &tracked, BPF_ANY);
    
    return 0;
}

// Monitor write syscall
SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    const void *buf = (void *)ctx->args[1];
    size_t count = ctx->args[2];
    
    // Check if we're tracking this fd
    u64 key = gen_pid_fd_key(pid, fd);
    bool *tracked = bpf_map_lookup_elem(&fd_track_map, &key);
    if (!tracked)
        return 0;
    
    struct modify_event *event;
    event = bpf_ringbuf_reserve(&modify_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill basic info
    event->pid = pid;
    event->tgid = id & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->fd = fd;
    event->count = count;
    event->offset = -1;  // Regular write, no offset specified
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Path will be resolved in userspace
    event->pathname[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Monitor pwrite64 syscall (write with offset)
SEC("tp/syscalls/sys_enter_pwrite64")
int trace_pwrite_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    const void *buf = (void *)ctx->args[1];
    size_t count = ctx->args[2];
    off_t offset = ctx->args[3];
    
    // Check if we're tracking this fd
    u64 key = gen_pid_fd_key(pid, fd);
    bool *tracked = bpf_map_lookup_elem(&fd_track_map, &key);
    if (!tracked)
        return 0;
    
    struct modify_event *event;
    event = bpf_ringbuf_reserve(&modify_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill basic info
    event->pid = pid;
    event->tgid = id & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->fd = fd;
    event->count = count;
    event->offset = offset;
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Path will be resolved in userspace
    event->pathname[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Monitor writev syscall
SEC("tp/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    
    // Check if we're tracking this fd
    u64 key = gen_pid_fd_key(pid, fd);
    bool *tracked = bpf_map_lookup_elem(&fd_track_map, &key);
    if (!tracked)
        return 0;
    
    struct modify_event *event;
    event = bpf_ringbuf_reserve(&modify_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill basic info
    event->pid = pid;
    event->tgid = id & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->fd = fd;
    event->count = 0;  // Can't easily calculate total write size for writev
    event->offset = -1;
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Path will be resolved in userspace
    event->pathname[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Cleanup fd tracking on close
SEC("tp/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = ctx->args[0];
    
    u64 key = gen_pid_fd_key(pid, fd);
    bpf_map_delete_elem(&fd_track_map, &key);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

