#include "fim_userspace.h"

// DEFINE the global variables
struct file_state *file_cache[MAX_FILE_CACHE] = {NULL};
int  cache_entries = 0;
FILE *log_file = NULL;
struct passwd *pw = NULL;
int stats_fd = -1;

// Initializing env with default values
struct env env = {
    .verbose = false,
    .timestamp = false,
    .print_uid = false,
    .exclude_dev_null = false,
    .exclude_tmp_files = false,
    .exclude_editor_noise = true,
    .strict_watch = false,
    .monitor_create = true,
    .monitor_delete = true,
    .monitor_write = true,
    .monitor_rename = true,
    .monitor_symlink = true,
    .monitor_time_change = true,
    .monitor_chown = true,
    .monitor_chmod = true,
    .show_flags = false,
    .content_aware = true,
    .ignore_unchanged = true,
    .enable_logging = true,
    .name_filter = NULL,
    .exclude_pattern_count = 0,
    .watch_pattern_count = 0,
    .pid = 0,
    .uid = 0
};

volatile sig_atomic_t exiting = 0;

