#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_create.h"
#include "file_create.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_BUFFER_TIME_MS	10
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_EXCLUDE_PATTERNS	64  // Maximum number of exclude patterns
#define AT_FDCWD		-100    // Special value for current working directory

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool exclude_dev_null;
	bool exclude_tmp_files;
	char *name_filter;
	char *exclude_patterns[MAX_EXCLUDE_PATTERNS];  // Array of exclude patterns
	int exclude_pattern_count;  // Number of exclude patterns
	__u32 pid;
	__u32 uid;
} env = {};

const char *argp_program_version = "file_create 1.0";
const char *argp_program_bug_address = "<your-email@example.com>";
const char argp_program_doc[] =
"Monitor file creation events via openat syscall with O_CREAT flag\n"
"\n"
"USAGE: file_create [-h] [-v] [-T] [-U] [-p PID] [-u UID] [--no-dev-null] [--no-tmp]\n"
"                   [-n NAME] [-e PATTERN] [-e PATTERN2] ...\n"
"\n"
"EXAMPLES:\n"
"    ./file_create               # trace all file creations\n"
"    ./file_create -T            # include timestamps\n"
"    ./file_create -U            # include UID\n"
"    ./file_create -p 1234       # trace specific PID\n"
"    ./file_create -u 1000       # trace specific UID\n"
"    ./file_create --no-dev-null # exclude /dev/null creations\n"
"    ./file_create --no-tmp      # exclude temporary files\n"
"    ./file_create -n main       # only show processes containing 'main'\n"
"    ./file_create -e '.tmp'     # exclude files containing '.tmp'\n"
"    ./file_create -e '.cache' -e '.mozilla' -e '/tmp/' # exclude multiple patterns\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "print-uid", 'U', NULL, 0, "Print UID", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "uid", 'u', "UID", 0, "User ID to trace", 0 },
	{ "no-dev-null", 1001, NULL, 0, "Exclude /dev/null file creations", 0 },
	{ "no-tmp", 1002, NULL, 0, "Exclude temporary files (containing .tmp, .swp, etc.)", 0 },
	{ "name", 'n', "NAME", 0, "Only trace processes containing NAME", 0 },
	{ "exclude", 'e', "PATTERN", 0, "Exclude files containing PATTERN (can be used multiple times)", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'p':
		errno = 0;
		env.pid = (__u32)strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'u':
		errno = 0;
		env.uid = (__u32)strtol(arg, NULL, 10);
		if (errno || (long)env.uid < 0) {
			fprintf(stderr, "Invalid UID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 1001:  // --no-dev-null
		env.exclude_dev_null = true;
		break;
	case 1002:  // --no-tmp
		env.exclude_tmp_files = true;
		break;
	case 'n':
		env.name_filter = arg;
		break;
	case 'e':
		if (env.exclude_pattern_count < MAX_EXCLUDE_PATTERNS) {
			env.exclude_patterns[env.exclude_pattern_count] = arg;
			env.exclude_pattern_count++;
		} else {
			fprintf(stderr, "Maximum number of exclude patterns (%d) exceeded\n", 
				MAX_EXCLUDE_PATTERNS);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

// Check if the filename matches any of the exclude patterns
static bool matches_exclude_patterns(const char *fname)
{
	for (int i = 0; i < env.exclude_pattern_count; i++) {
		if (strstr(fname, env.exclude_patterns[i]))
			return true;
	}
	return false;
}

// Get the current working directory of a process
static char *get_process_cwd(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
	
	static char cwd[PATH_MAX];
	ssize_t len = readlink(path, cwd, sizeof(cwd) - 1);
	if (len != -1) {
		cwd[len] = '\0';
		return cwd;
	}
	return NULL;
}

// Get the path associated with a file descriptor
static char *get_fd_path(pid_t pid, int fd)
{
	char path[64];
	if (fd == AT_FDCWD) {
		return get_process_cwd(pid);
	}
	
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	
	static char fd_path[PATH_MAX];
	ssize_t len = readlink(path, fd_path, sizeof(fd_path) - 1);
	if (len != -1) {
		fd_path[len] = '\0';
		return fd_path;
	}
	return NULL;
}

// Resolve full path from dirfd and filename
static char *resolve_full_path(pid_t pid, int dirfd, const char *fname)
{
	static char full_path[PATH_MAX];
	
	// If filename is already absolute, return it as-is
	if (fname[0] == '/') {
		strncpy(full_path, fname, PATH_MAX - 1);
		full_path[PATH_MAX - 1] = '\0';
		return full_path;
	}
	
	// Get the directory path from dirfd
	char *dir_path = get_fd_path(pid, dirfd);
	if (!dir_path) {
		// Fallback to just the filename if we can't resolve the directory
		strncpy(full_path, fname, PATH_MAX - 1);
		full_path[PATH_MAX - 1] = '\0';
		return full_path;
	}
	
	// Combine directory path and filename
	// Ensure the combined path won't exceed PATH_MAX
	size_t dir_len = strlen(dir_path);
	size_t fname_len = strlen(fname);
	
	if (dir_len + 1 + fname_len >= PATH_MAX - 1) {
		// Combined path would be too long, return just the filename
		strncpy(full_path, fname, PATH_MAX - 1);
		full_path[PATH_MAX - 1] = '\0';
	} else {
		// Safe to combine paths
		memcpy(full_path, dir_path, dir_len);
		full_path[dir_len] = '/';
		memcpy(full_path + dir_len + 1, fname, fname_len);
		full_path[dir_len + 1 + fname_len] = '\0';
	}
	return full_path;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct create_event *event = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char *full_path;

	// Apply filters
	if (env.pid && env.pid != event->pid)
		return;
	if (env.uid && env.uid != event->uid)
		return;
	
	// Filter by process name
	if (env.name_filter && !strstr(event->comm, env.name_filter))
		return;
	
	// Resolve the full path
	full_path = resolve_full_path(event->pid, event->dirfd, event->fname);
	
	// Filter out /dev/null if requested
	if (env.exclude_dev_null && strcmp(full_path, "/dev/null") == 0)
		return;
	
	// Filter out temporary files if requested
	if (env.exclude_tmp_files) {
		if (strstr(full_path, ".tmp") || 
		    strstr(full_path, ".swp") ||
		    strstr(full_path, ".tmpfile") ||
		    strstr(full_path, "/.cache/") ||
		    (strstr(full_path, event->comm) && strstr(full_path, "/.mozilla/")))
			return;
	}
	
	// Check custom exclude patterns
	if (matches_exclude_patterns(full_path))
		return;

	// Prepare timestamp
	if (env.timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}

	// Print UID if requested
	if (env.print_uid)
		printf("%-7u ", event->uid);

	// Main output - now with full path
	printf("%-6u %-16s %08o %04o %s\n",
	       event->pid, event->comm, event->flags, event->mode, full_path);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct file_create_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	// Open BPF program
	obj = file_create_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	// Load BPF program  
	err = file_create_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	// Attach BPF program
	err = file_create_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	// Print headers
	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_uid)
		printf("%-7s ", "UID");
	printf("%-6s %-16s %-8s %-4s %s\n", "PID", "COMM", "FLAGS", "MODE", "PATH");

	// Setup perf buffer
	pb = perf_buffer__new(bpf_map__fd(obj->maps.create_events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	// Setup signal handler
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing file creation events. Hit Ctrl-C to stop.\n");

	// Main event loop
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	file_create_bpf__destroy(obj);
	return err != 0;
}



