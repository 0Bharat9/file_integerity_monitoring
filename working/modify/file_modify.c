#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_modify.h"
#include "file_modify.skel.h"

#define PERF_POLL_TIMEOUT_MS   100
#define MAX_EXCLUDE_PATTERNS   64  // Maximum number of exclude patterns
#define MAX_TRACKED_FILES      1024 // Maximum number of files to track

static volatile sig_atomic_t exiting = 0;

struct env {
    bool verbose;
    bool timestamp;
    bool print_uid;
    bool print_bytes;
    bool print_offset;
    bool exclude_tmp_files;
    bool show_summary;       // Changed from show_only_summary to show_summary
    bool skip_unknown;       // Added to skip [unknown] paths
    int min_bytes;           // Minimum number of bytes to report
    char *name_filter;
    char *path_filter;
    char *exclude_patterns[MAX_EXCLUDE_PATTERNS];
    int exclude_pattern_count;
    __u32 pid;
    __u32 uid;
} env = {
    .min_bytes = 0,
    .skip_unknown = false,  // Default to showing unknown paths
};

// Structure to track write statistics for files
struct file_stats {
    unsigned long write_count;
    unsigned long long bytes_written;
    time_t first_seen;
    time_t last_seen;
    char path[PATH_MAX];
};

// Global array to track file statistics
static struct file_stats file_stats[MAX_TRACKED_FILES];
static int file_stats_count = 0;

const char *argp_program_version = "file_modify 1.0";
const char *argp_program_bug_address = "<your-email@example.com>";
const char argp_program_doc[] =
"Monitor file modification events via write syscalls\n"
"\n"
"USAGE: file_modify [-h] [-v] [-T] [-U] [-B] [-O] [-S] [-M bytes] [-p PID] [-u UID] [--no-tmp]\n"
"                  [-n NAME] [-P PATH] [-e PATTERN] [-e PATTERN2] ... [--skip-unknown]\n"
"\n"
"EXAMPLES:\n"
"    ./file_modify               # trace all file modifications\n"
"    ./file_modify -T            # include timestamps\n"
"    ./file_modify -U            # include UID\n"
"    ./file_modify -B            # show bytes written\n"
"    ./file_modify -O            # show write offset\n"
"    ./file_modify -S            # show summary at end\n"
"    ./file_modify -M 1024       # only show writes >= 1024 bytes\n"
"    ./file_modify -p 1234       # trace specific PID\n"
"    ./file_modify -u 1000       # trace specific UID\n"
"    ./file_modify --no-tmp      # exclude temporary files\n"
"    ./file_modify --skip-unknown # skip [unknown] paths\n"
"    ./file_modify -n firefox    # only show processes containing 'firefox'\n"
"    ./file_modify -P /home/user # only show files under /home/user\n"
"    ./file_modify -e '.tmp'     # exclude files containing '.tmp'\n"
"    ./file_modify -e '.cache' -e '.mozilla' # exclude multiple patterns\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
    { "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
    { "print-uid", 'U', NULL, 0, "Print UID", 0 },
    { "print-bytes", 'B', NULL, 0, "Print bytes written", 0 },
    { "print-offset", 'O', NULL, 0, "Print write offset", 0 },
    { "summary", 'S', NULL, 0, "Show summary at end", 0 },
    { "min-bytes", 'M', "BYTES", 0, "Minimum bytes to report", 0 },
    { "pid", 'p', "PID", 0, "Process ID to trace", 0 },
    { "uid", 'u', "UID", 0, "User ID to trace", 0 },
    { "no-tmp", 1001, NULL, 0, "Exclude temporary files", 0 },
    { "skip-unknown", 1002, NULL, 0, "Skip [unknown] paths", 0 },
    { "name", 'n', "NAME", 0, "Only trace processes containing NAME", 0 },
    { "path", 'P', "PATH", 0, "Only trace files under PATH", 0 },
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
    case 'B':
        env.print_bytes = true;
        break;
    case 'O':
        env.print_offset = true;
        break;
    case 'S':
        env.show_summary = true;
        break;
    case 'M':
        errno = 0;
        env.min_bytes = atoi(arg);
        if (errno || env.min_bytes < 0) {
            fprintf(stderr, "Invalid minimum bytes: %s\n", arg);
            argp_usage(state);
        }
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
    case 1001:  // --no-tmp
        env.exclude_tmp_files = true;
        break;
    case 1002:  // --skip-unknown
        env.skip_unknown = true;
        break;
    case 'n':
        env.name_filter = arg;
        break;
    case 'P':
        env.path_filter = arg;
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

// Get the path for a file descriptor with better error handling
static const char *get_fd_path(pid_t pid, int fd)
{
    static char path_buf[PATH_MAX];
    char fd_path[64];
    
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
    
    ssize_t len = readlink(fd_path, path_buf, sizeof(path_buf) - 1);
    if (len != -1) {
        path_buf[len] = '\0';
        return path_buf;
    }
    
    return NULL;
}

// Check if the filename matches any of the exclude patterns
static bool matches_exclude_patterns(const char *fname)
{
    if (!fname)
        return true;  // Exclude if path is NULL
    
    for (int i = 0; i < env.exclude_pattern_count; i++) {
        if (strstr(fname, env.exclude_patterns[i]))
            return true;
    }
    
    return false;
}

// Check if path is under specified path filter
static bool is_under_path(const char *path, const char *filter)
{
    if (!filter || !path)
        return true;  // No filter means include all
    
    return strncmp(path, filter, strlen(filter)) == 0;
}

// Check if path is likely a temporary file
static bool is_temp_file(const char *path)
{
    if (!path)
        return false;
    
    return strstr(path, ".tmp") || 
           strstr(path, ".swp") ||
           strstr(path, ".tmpfile") ||
           strstr(path, "/.cache/") ||
           strstr(path, "/tmp/") ||
           strstr(path, "/var/tmp/") ||
           strstr(path, "tmp_pack_");  // Added to exclude git tmp pack files
}

// Update file statistics
static void update_file_stats(const char *path, size_t bytes)
{
    time_t now = time(NULL);
    int i;
    
    // Check if file is already being tracked
    for (i = 0; i < file_stats_count; i++) {
        if (strcmp(file_stats[i].path, path) == 0) {
            file_stats[i].write_count++;
            file_stats[i].bytes_written += bytes;
            file_stats[i].last_seen = now;
            return;
        }
    }
    
    // If not tracked and we have space, add it
    if (file_stats_count < MAX_TRACKED_FILES) {
        strncpy(file_stats[file_stats_count].path, path, PATH_MAX - 1);
        file_stats[file_stats_count].path[PATH_MAX - 1] = '\0';
        file_stats[file_stats_count].write_count = 1;
        file_stats[file_stats_count].bytes_written = bytes;
        file_stats[file_stats_count].first_seen = now;
        file_stats[file_stats_count].last_seen = now;
        file_stats_count++;
    }
}

// Print file statistics summary
static void print_file_stats_summary(void)
{
    printf("\n=== File Modification Summary ===\n");
    printf("%-50s %-10s %-15s %s\n", "File Path", "Writes", "Bytes Written", "Last Modified");
    
    for (int i = 0; i < file_stats_count; i++) {
        struct tm *tm;
        char ts[32];
        
        tm = localtime(&file_stats[i].last_seen);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        
        char bytes_str[32];
        if (file_stats[i].bytes_written < 1024) {
            snprintf(bytes_str, sizeof(bytes_str), "%llu B", file_stats[i].bytes_written);
        } else if (file_stats[i].bytes_written < 1024 * 1024) {
            snprintf(bytes_str, sizeof(bytes_str), "%.2f KB", 
                     (double)file_stats[i].bytes_written / 1024);
        } else {
            snprintf(bytes_str, sizeof(bytes_str), "%.2f MB", 
                     (double)file_stats[i].bytes_written / (1024 * 1024));
        }
        
        printf("%-50s %-10lu %-15s %s\n", 
               file_stats[i].path, 
               file_stats[i].write_count, 
               bytes_str,
               ts);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct modify_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    const char *full_path;

    // Apply filters
    if (env.pid && env.pid != e->pid)
        return 0;
    if (env.uid && env.uid != e->uid)
        return 0;
    if (env.min_bytes > 0 && e->count < (size_t)env.min_bytes)
        return 0;
    
    // Filter by process name
    if (env.name_filter && !strstr(e->comm, env.name_filter))
        return 0;
    
    // Resolve file path
    full_path = e->pathname;
    if (full_path[0] == '\0') {
        // If path not provided in event, try to resolve it
        full_path = get_fd_path(e->pid, e->fd);
        if (!full_path) {
            // If we can't resolve, use a placeholder
            full_path = "[unknown]";
            // Skip unknown paths if requested
            if (env.skip_unknown) {
                return 0;
            }
        }
    }
    
    // Filter by path
    if (!is_under_path(full_path, env.path_filter))
        return 0;
    
    // Filter out temporary files if requested
    if (env.exclude_tmp_files && is_temp_file(full_path))
        return 0;
    
    // Check custom exclude patterns
    if (matches_exclude_patterns(full_path))
        return 0;

    // Update statistics 
    update_file_stats(full_path, e->count);
    
    // If we're only showing summary, don't print individual events
    if (env.show_summary && !env.verbose)
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
    printf("%-6u %-16s ", e->pid, e->comm);
    
    // Print bytes if requested
    if (env.print_bytes) {
        if (e->count < 1024) {
            printf("%-10zu B  ", e->count);
        } else if (e->count < 1024 * 1024) {
            printf("%-10.2f KB ", (double)e->count / 1024);
        } else {
            printf("%-10.2f MB ", (double)e->count / (1024 * 1024));
        }
    }
    
    // Print offset if requested
    if (env.print_offset) {
        if (e->offset >= 0) {
            printf("@%-10lld ", (long long)e->offset);
        } else {
            printf("%-11s ", "APPEND");
        }
    }
    
    printf("%s\n", full_path);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct ring_buffer *rb = NULL;
    struct file_modify_bpf *obj;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    // Open BPF program
    obj = file_modify_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    // Load & verify BPF program
    err = file_modify_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // Attach BPF program
    err = file_modify_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(obj->maps.modify_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }

    // Setup signal handler
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    // Print headers
    if (env.timestamp)
        printf("%-8s ", "TIME");
    if (env.print_uid)
        printf("%-7s ", "UID");
    printf("%-6s %-16s ", "PID", "COMM");
    if (env.print_bytes)
        printf("%-10s ", "BYTES");
    if (env.print_offset)
        printf("%-11s ", "OFFSET");
    printf("%s\n", "PATH");

    printf("Tracing file modification events. Hit Ctrl-C to stop.\n");

    // Main event loop
    while (!exiting) {
        err = ring_buffer__poll(rb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling ring buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        err = 0;
    }
    
    // Print summary at the end if requested
    if (env.show_summary) {
        print_file_stats_summary();
    }

cleanup:
    ring_buffer__free(rb);
    file_modify_bpf__destroy(obj);
    return err != 0;
}

