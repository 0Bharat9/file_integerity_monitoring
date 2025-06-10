#include "event_handler.h"
#include "file_monitor.h"
#include "json_logger.h"
#include "system_info.h"
#include "fim.skel.h"

// Remove the global variable definitions from here since they're in globals.c
// Just declare them as extern or rely on the header files

const char *argp_program_version = "fim 2.2";
const char *argp_program_bug_address = "bharatexhash09@gmail.com";
const char argp_program_doc[] =
"Enhanced File Integrity Monitor - Monitor file creation, deletion, and write events\n"
"NEW: Content-aware monitoring and JSON logging to /var/log/fim.log\n"
"\n"
"USAGE: fim [-h] [-v] [-T] [-U] [-F] [-p PID] [-u UID] [--no-dev-null] [--no-tmp]\n"
"           [--no-editor-filter] [--no-content-check] [--show-unchanged] [--no-log]\n"
"           [-n NAME] [-e PATTERN] [-w PATTERN] [--strict] [--create-only] [--delete-only] [--write-only]\n"
"           [--rename-only] [--symlink-only] [--time-change-only]\n"
"\n"
"EXAMPLES:\n"
"    ./fim                       # content-aware monitoring with JSON logging\n"
"    ./fim --no-log              # disable JSON logging to file\n"
"    ./fim --show-unchanged      # show all save events, even if content unchanged\n"
"    ./fim --no-content-check    # disable content checking (faster, less accurate)\n"
"    ./fim -T -U                 # include timestamps and UIDs\n"
"    ./fim --strict -w '/home/user/docs/' # strict watching with content awareness\n";

// Command line options
static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
    { "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
    { "print-uid", 'U', NULL, 0, "Print UID", 0 },
    { "show-flags", 'F', NULL, 0, "Show file flags and mode for create events", 0 },
    { "pid", 'p', "PID", 0, "Process ID to trace", 0 },
    { "uid", 'u', "UID", 0, "User ID to trace", 0 },
    { "no-dev-null", 1001, NULL, 0, "Exclude /dev/null file operations", 0 },
    { "no-tmp", 1002, NULL, 0, "Exclude temporary files", 0 },
    { "no-editor-filter", 1010, NULL, 0, "Disable filtering of editor temporary files", 0 },
    { "no-content-check", 1011, NULL, 0, "Disable content change detection", 0 },
    { "show-unchanged", 1012, NULL, 0, "Show write events even when file content hasn't changed", 0 },
    { "no-log", 1013, NULL, 0, "Disable JSON logging to /var/log/fim.log", 0 },
    { "strict", 1003, NULL, 0, "Enable strict watching mode", 0 },
    { "create-only", 1004, NULL, 0, "Monitor only file creation events", 0 },
    { "delete-only", 1005, NULL, 0, "Monitor only file deletion events", 0 },
    { "write-only", 1006, NULL, 0, "Monitor only file write events", 0 },
    { "rename-only", 1017, NULL, 0, "Monitor only file rename events", 0 },
    { "symlink-only", 1018, NULL, 0, "Monitor only file symlink events", 0 },
    { "time-only", 1019, NULL, 0, "Monitor only file time_stamp_change events", 0 },
    { "no-create", 1007, NULL, 0, "Disable monitoring of file creation events", 0 },
    { "no-delete", 1008, NULL, 0, "Disable monitoring of file deletion events", 0 },
    { "no-write", 1009, NULL, 0, "Disable monitoring of file write events", 0 },
    { "no-rename", 1014, NULL, 0, "Disable monitoring of file rename events", 0 },
    { "no-symlink", 1015, NULL, 0, "Disable monitoring of file symlink events", 0 },
    { "no-time-change", 1016, NULL, 0, "Disable monitoring of file timestamp change events", 0 },
    { "name", 'n', "NAME", 0, "Only trace processes containing NAME", 0 },
    { "exclude", 'e', "PATTERN", 0, "Exclude files containing PATTERN", 0 },
    { "watch", 'w', "PATTERN", 0, "Watch only files containing PATTERN (requires --strict)", 0 },
    {},
};

void initialize_globals(void) {
    // Initialize the passwd structure
    pw = getpwuid(getuid());
    if (!pw) {
        fprintf(stderr, "Warning: Could not get user information\n");
    }
    
    // Initialize other globals as needed
    memset(file_cache, 0, sizeof(file_cache));
    cache_entries = 0;
    
    // Open log file if logging is enabled
    if (env.enable_logging) {
        log_file = fopen(LOG_FILE_PATH, "a");
        if (!log_file) {
            fprintf(stderr, "Warning: Could not open log file %s\n", LOG_FILE_PATH);
        }
    }
}

// Signal handler
static void sig_int(int signo)
{
    exiting = 1;
}

// libbpf print function
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

// Argument parsing
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
	case 'F':
		env.show_flags = true;
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
	case 1010:  // --no-editor-filter
		env.exclude_editor_noise = false;
		break;
	case 1011:  // --no-content-check
		env.content_aware = false;
		break;
	case 1012:  // --show-unchanged
		env.ignore_unchanged = false;
		break;
	case 1013:  // --no-log
		env.enable_logging = false;
		break;
	case 1003:  // --strict
		env.strict_watch = true;
		break;
	case 1004:  // --create-only
		env.monitor_create = true;
		env.monitor_delete = false;
		env.monitor_write = false;
    env.monitor_rename = false;
    env.monitor_symlink = false;
    env.monitor_time_change = false;
		break;
	case 1005:  // --delete-only
		env.monitor_create = false;
		env.monitor_delete = true;
		env.monitor_write = false;
    env.monitor_rename = false;
    env.monitor_symlink = false;
    env.monitor_time_change = false;
    break;
	case 1006:  // --write-only
		env.monitor_create = false;
		env.monitor_delete = false;
		env.monitor_write = true;
		env.monitor_rename = false;
    env.monitor_symlink = false;
    env.monitor_time_change = false;
    break;
  case 1017:
    env.monitor_create = false;
		env.monitor_delete = false;
		env.monitor_write = false;
		env.monitor_rename = true;
    env.monitor_symlink = false;
    env.monitor_time_change = false;
	case 1018:
    env.monitor_create = false;
		env.monitor_delete = false;
		env.monitor_write = false;
		env.monitor_rename = false;
    env.monitor_symlink = true;
    env.monitor_time_change = false;
  case 1019:
    env.monitor_create = false;
		env.monitor_delete = false;
		env.monitor_write = false;
		env.monitor_rename = false;
    env.monitor_symlink = false;
    env.monitor_time_change = true;
  case 1007:  // --no-create
		env.monitor_create = false;
		break;
	case 1008:  // --no-delete
		env.monitor_delete = false;
		break;
	case 1009:  // --no-write
		env.monitor_write = false;
		break;
  case 1014:  // --no-write
		env.monitor_rename = false;
		break;
	case 1015:  // --no-write
		env.monitor_symlink = false;
		break;
	case 1016:  // --no-write
		env.monitor_time_change = false;
		break;
	case 'n':
		env.name_filter = arg;
		break;
	case 'e':
		if (env.exclude_pattern_count < MAX_EXCLUDE_PATTERNS) {
			env.exclude_patterns[env.exclude_pattern_count] = arg;
			env.exclude_pattern_count++;
		} else {
			fprintf(stderr, "Maximum number of exclude patterns exceeded\n");
			argp_usage(state);
		}
		break;
	case 'w':
		if (env.watch_pattern_count < MAX_WATCH_PATTERNS) {
			env.watch_patterns[env.watch_pattern_count] = arg;
			env.watch_pattern_count++;
		} else {
			fprintf(stderr, "Maximum number of watch patterns exceeded\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env.strict_watch && env.watch_pattern_count == 0) {
			fprintf(stderr, "Error: --strict mode requires at least one -w pattern\n");
			argp_usage(state);
		}
		if (!env.strict_watch && env.watch_pattern_count > 0) {
			fprintf(stderr, "Warning: -w patterns specified but --strict mode not enabled\n");
		}
		if (!env.monitor_create && !env.monitor_delete && !env.monitor_write) {
			fprintf(stderr, "Error: At least one event type must be monitored\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct fim_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);
  
  init_system_info();     // Initialize hostname, IP, user info
    if (!init_logging()) {  // Initialize logging
        fprintf(stderr, "Warning: Logging initialization failed\n");
    }
	
  skel = fim_bpf__open_and_load();	
  if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = fim_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs\n");
		goto cleanup;
	}
  
  stats_fd = bpf_map__fd(skel->maps.stats_map);
  if (stats_fd < 0) {
    fprintf(stderr, "Warning: Could not get stats map fd\n");
    goto cleanup;
  }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.fim_events), handle_event, NULL, NULL);
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

	print_configuration();
	print_header();
	printf("Hit Ctrl-C to stop.\n");

	// Main event loop
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	if (stats_fd >= 0) {
        print_stats(stats_fd);
  }
  ring_buffer__free(rb);
	fim_bpf__destroy(skel);
  cleanup_logging();      // ADD: Clean up logging
  cleanup_file_cache();   // ADD: Clean up file cache
	return err;
}

