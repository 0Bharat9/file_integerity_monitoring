#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include "unlink_monitor.skel.h"
#include "unlink_monitor.h"

#define AT_FDCWD -100
#define MAX_EXCLUDE_PATTERNS 64

static volatile sig_atomic_t exiting = 0;

struct env {
    bool verbose;
    bool timestamp;
    bool print_uid;
    bool exclude_tmp_files;
    char *name_filter;
    char *exclude_patterns[MAX_EXCLUDE_PATTERNS];
    int exclude_pattern_count;
    __u32 pid;
    __u32 uid;
} env = {};

const char *argp_program_version = "unlink_monitor 1.0";
const char *argp_program_bug_address = "<your-email@example.com>";
const char argp_program_doc[] =
"Monitor file deletion events via unlinkat syscall\n"
"\n"
"USAGE: unlink_monitor [-h] [-v] [-T] [-U] [-p PID] [-u UID] [--no-tmp]\n"
"                      [-n NAME] [-e PATTERN] [-e PATTERN2] ...\n"
"\n"
"EXAMPLES:\n"
"    ./unlink_monitor               # trace all file deletions\n"
"    ./unlink_monitor -T            # include timestamps\n"
"    ./unlink_monitor -U            # include UID\n"
"    ./unlink_monitor -p 1234       # trace specific PID\n"
"    ./unlink_monitor -u 1000       # trace specific UID\n"
"    ./unlink_monitor --no-tmp      # exclude temporary files\n"
"    ./unlink_monitor -n main       # only show processes containing 'main'\n"
"    ./unlink_monitor -e '.tmp'     # exclude files containing '.tmp'\n"
"    ./unlink_monitor -e '.cache' -e '.mozilla' # exclude multiple patterns\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
    { "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
    { "print-uid", 'U', NULL, 0, "Print UID", 0 },
    { "pid", 'p', "PID", 0, "Process ID to trace", 0 },
    { "uid", 'u', "UID", 0, "User ID to trace", 0 },
    { "no-tmp", 1002, NULL, 0, "Exclude temporary files", 0 },
    { "name", 'n', "NAME", 0, "Only trace processes containing NAME", 0 },
    { "exclude", 'e', "PATTERN", 0, "Exclude files containing PATTERN", 0 },
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

// Get the path associated with a file descriptor
static char *get_fd_path(pid_t pid, int fd)
{
    static char fd_path[PATH_MAX];
    char path[64];
    
    if (fd == AT_FDCWD) {
        snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    } else {
        snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    }
    
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

// Check if the filename matches any of the exclude patterns
static bool matches_exclude_patterns(const char *fname)
{
    for (int i = 0; i < env.exclude_pattern_count; i++) {
        if (strstr(fname, env.exclude_patterns[i]))
            return true;
    }
    return false;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    char *full_path;

    // Apply filters
    if (env.pid && env.pid != e->pid)
        return 0;
    if (env.uid && env.uid != e->uid)
        return 0;
    
    // Filter by process name
    if (env.name_filter && !strstr(e->comm, env.name_filter))
        return 0;
    
    // Skip if filename is empty
    if (e->filename[0] == '\0')
        return 0;
    
    // Resolve the full path
    full_path = resolve_full_path(e->pid, e->dfd, e->filename);
    
    // Filter out temporary files if requested
    if (env.exclude_tmp_files) {
        if (strstr(full_path, ".tmp") || 
            strstr(full_path, ".swp") ||
            strstr(full_path, ".tmpfile") ||
            strstr(full_path, "/.cache/") ||
            (strstr(full_path, e->comm) && strstr(full_path, "/.mozilla/")))
            return 0;
    }
    
    // Check custom exclude patterns
    if (matches_exclude_patterns(full_path))
        return 0;

    // Skip common system temporary files
    if (strstr(full_path, "/tmp/") ||
        strstr(full_path, "/var/tmp/") ||
        strstr(e->comm, "systemd") ||
        strstr(e->comm, "kworker") ||
        strstr(e->comm, "ksoftirqd") ||
        strstr(e->comm, "migration") ||
        strstr(e->comm, "rcu_") ||
        strstr(e->comm, "watchdog"))
        return 0;
    
    // Skip empty or invalid filenames
    if (strlen(full_path) == 0)
        return 0;

    // Prepare timestamp
    if (env.timestamp) {
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%-8s ", ts);
    }

    // Print UID if requested
    if (env.print_uid)
        printf("%-7u ", e->uid);

    // Main output
    printf("%-6u %-16s %s\n", e->pid, e->comm, full_path);
    return 0;
}

static void print_header() {
    if (env.timestamp)
        printf("%-8s ", "TIME");
    if (env.print_uid)
        printf("%-7s ", "UID");
    printf("%-6s %-16s %s\n", "PID", "COMM", "PATH");
}

int main(int argc, char **argv) {
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct unlink_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    // Open and load the BPF program
    skel = unlink_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Attach kprobe
    err = unlink_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    // Set up ringbuf
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // Setup signal handler
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    print_header();
    printf("Tracing file deletion events. Hit Ctrl-C to stop.\n");

    // Poll events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    unlink_monitor_bpf__destroy(skel);
    return err;
}

