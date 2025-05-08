#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define FILENAME_LEN 256

struct event {
    u32 pid;
    char filename[FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    struct event *e;
    const char *filename_ptr;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    filename_ptr = BPF_CORE_READ(name, name);

    if (filename_ptr)
        bpf_probe_read_str(e->filename, sizeof(e->filename), filename_ptr);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

