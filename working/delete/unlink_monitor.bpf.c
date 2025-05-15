#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "unlink_monitor.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    struct event *e;
    const char *fname;
    struct dentry *dentry;
    struct path path;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Get PID and thread group ID
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tgid = id;
    
    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Get UID
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Get dfd (directory file descriptor)
    e->dfd = dfd;
    
    // Extract filename
    fname = BPF_CORE_READ(name, name);
    if (fname) {
        bpf_probe_read_str(&e->filename, sizeof(e->filename), fname);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


