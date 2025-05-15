#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "file_create.h"

#ifndef O_CREAT
#define O_CREAT		00000100
#endif

// Structure for tracepoint context
struct syscall_trace_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int nr;
	unsigned long args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} create_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscall_trace_enter* ctx)
{
	struct create_event event = {};
	const char *fname;
	int flags;
	__u64 id;
	__u32 tgid, pid;
	
	// Get process ID and thread group ID
	id = bpf_get_current_pid_tgid();
	tgid = (__u32)(id >> 32);
	pid = (__u32)id;
	
	// Extract system call arguments
	// dirfd is args[0], but we'll get the current working directory from userspace
	fname = (const char *)ctx->args[1];  // filename is 2nd argument (args[1])
	flags = (int)ctx->args[2];          // flags is 3rd argument (args[2])
	
	// Check if O_CREAT flag is set
	if (!(flags & O_CREAT))
		return 0;  // Not a file creation, skip it
	
	// Fill event structure
	event.pid = pid;
	event.tgid = tgid;
	event.uid = (__u32)bpf_get_current_uid_gid();
	event.flags = flags;
	event.mode = (__u32)ctx->args[3];  // mode is 4th argument (args[3])
	event.dirfd = (int)ctx->args[0];   // directory file descriptor
	
	// Get process name and filename
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), fname);
	
	// Send event to userspace
	bpf_perf_event_output(ctx, &create_events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	
	return 0;
}

char _license[] SEC("license") = "GPL";


