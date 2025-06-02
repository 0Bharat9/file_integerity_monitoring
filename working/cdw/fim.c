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
#include <errno.h>
#include <limits.h>
#include <openssl/evp.h>
#include "fim.h"
#include "fim.skel.h"

#define MAX_EXCLUDE_PATTERNS	64   
#define MAX_WATCH_PATTERNS	64    
#define AT_FDCWD		-100     
#define MAX_FILE_CACHE		1000  // Maximum number of files to track
#define HASH_SIZE		16    // MD5 hash size

static volatile sig_atomic_t exiting = 0;

// Structure to track file states
struct file_state {
	char path[PATH_MAX];
	unsigned char hash[HASH_SIZE];
	time_t last_modified;
	struct file_state *next;
};

// Simple hash table for file tracking
static struct file_state *file_cache[MAX_FILE_CACHE];
static int cache_entries = 0;

static struct env {
	bool verbose;
	bool timestamp;  
	bool print_uid;
	bool exclude_dev_null;
	bool exclude_tmp_files;
	bool exclude_editor_noise;   
	bool strict_watch;           
	bool monitor_create;         
	bool monitor_delete;         
	bool monitor_write;          
	bool show_flags;             
	bool content_aware;          // NEW: Enable content-aware monitoring
	bool ignore_unchanged;       // NEW: Ignore saves with no content changes
	char *name_filter;
	char *exclude_patterns[MAX_EXCLUDE_PATTERNS];  
	int exclude_pattern_count;   
	char *watch_patterns[MAX_WATCH_PATTERNS];     
	int watch_pattern_count;     
	__u32 pid;
	__u32 uid;
} env = {
	.monitor_create = true,      
	.monitor_delete = true,
	.monitor_write = true,       
	.show_flags = false,         
	.exclude_editor_noise = true, 
	.content_aware = true,       // Default: enable content awareness
	.ignore_unchanged = true,    // Default: ignore unchanged saves
};

const char *argp_program_version = "fim 2.1";
const char *argp_program_bug_address = "bharatexhash09@gmail.com";
const char argp_program_doc[] =
"Enhanced File Integrity Monitor - Monitor file creation, deletion, and write events\n"
"NEW: Content-aware monitoring to avoid duplicate events for unchanged files\n"
"\n"
"USAGE: fim [-h] [-v] [-T] [-U] [-F] [-p PID] [-u UID] [--no-dev-null] [--no-tmp]\n"
"           [--no-editor-filter] [--no-content-check] [--show-unchanged] [-n NAME] \n"
"           [-e PATTERN] [-w PATTERN] [--strict] [--create-only] [--delete-only] [--write-only]\n"
"\n"
"EXAMPLES:\n"
"    ./fim                       # content-aware monitoring (ignores unchanged saves)\n"
"    ./fim --show-unchanged      # show all save events, even if content unchanged\n"
"    ./fim --no-content-check    # disable content checking (faster, less accurate)\n"
"    ./fim -T -U                 # include timestamps and UIDs\n"
"    ./fim --strict -w '/home/user/docs/' # strict watching with content awareness\n";

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
	{ "no-content-check", 1011, NULL, 0, "Disable content change detection (faster but less accurate)", 0 },
	{ "show-unchanged", 1012, NULL, 0, "Show write events even when file content hasn't changed", 0 },
	{ "strict", 1003, NULL, 0, "Enable strict watching mode", 0 },
	{ "create-only", 1004, NULL, 0, "Monitor only file creation events", 0 },
	{ "delete-only", 1005, NULL, 0, "Monitor only file deletion events", 0 },
	{ "write-only", 1006, NULL, 0, "Monitor only file write events", 0 },
	{ "no-create", 1007, NULL, 0, "Disable monitoring of file creation events", 0 },
	{ "no-delete", 1008, NULL, 0, "Disable monitoring of file deletion events", 0 },
	{ "no-write", 1009, NULL, 0, "Disable monitoring of file write events", 0 },
	{ "name", 'n', "NAME", 0, "Only trace processes containing NAME", 0 },
	{ "exclude", 'e', "PATTERN", 0, "Exclude files containing PATTERN", 0 },
	{ "watch", 'w', "PATTERN", 0, "Watch only files containing PATTERN (requires --strict)", 0 },
	{},
};

// Hash function for file paths
static unsigned int hash_path(const char *path) {
	unsigned int hash = 5381;
	int c;
	while ((c = *path++))
		hash = ((hash << 5) + hash) + c;
	return hash % MAX_FILE_CACHE;
}

// Calculate MD5 hash of file content
static bool calculate_file_hash(const char *filepath, unsigned char *hash) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return false;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return false;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return false;
    }
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return false;
        }
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return false;
    }
    
    EVP_MD_CTX_free(ctx);
    fclose(file);
    return true;
}


// Get or create file state entry
static struct file_state *get_file_state(const char *path) {
	unsigned int idx = hash_path(path);
	struct file_state *entry = file_cache[idx];
	
	// Search for existing entry
	while (entry) {
		if (strcmp(entry->path, path) == 0) {
			return entry;
		}
		entry = entry->next;
	}
	
	// Create new entry if not found and cache isn't full
	if (cache_entries < MAX_FILE_CACHE) {
		entry = malloc(sizeof(struct file_state));
		if (entry) {
			strncpy(entry->path, path, PATH_MAX - 1);
			entry->path[PATH_MAX - 1] = '\0';
			memset(entry->hash, 0, HASH_SIZE);
			entry->last_modified = 0;
			entry->next = file_cache[idx];
			file_cache[idx] = entry;
			cache_entries++;
		}
	}
	
	return entry;
}

// Check if file content has actually changed
static bool has_content_changed(const char *filepath) {
	if (!env.content_aware) {
		return true;  // If content checking disabled, assume changed
	}
	
	struct file_state *state = get_file_state(filepath);
	if (!state) {
		return true;  // If can't track, assume changed
	}
	
	unsigned char new_hash[HASH_SIZE];
	if (!calculate_file_hash(filepath, new_hash)) {
		return true;  // If can't read file, assume changed
	}
	
	// Compare with stored hash
	bool changed = (memcmp(state->hash, new_hash, HASH_SIZE) != 0);
	
	// Update stored hash if changed or if this is first time
	if (changed || state->last_modified == 0) {
		memcpy(state->hash, new_hash, HASH_SIZE);
		state->last_modified = time(NULL);
	}
	
	return changed;
}

// Clean up file cache
static void cleanup_file_cache() {
	for (int i = 0; i < MAX_FILE_CACHE; i++) {
		struct file_state *entry = file_cache[i];
		while (entry) {
			struct file_state *next = entry->next;
			free(entry);
			entry = next;
		}
		file_cache[i] = NULL;
	}
	cache_entries = 0;
}

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
	case 1003:  // --strict
		env.strict_watch = true;
		break;
	case 1004:  // --create-only
		env.monitor_create = true;
		env.monitor_delete = false;
		env.monitor_write = false;
		break;
	case 1005:  // --delete-only
		env.monitor_create = false;
		env.monitor_delete = true;
		env.monitor_write = false;
		break;
	case 1006:  // --write-only
		env.monitor_create = false;
		env.monitor_delete = false;
		env.monitor_write = true;
		break;
	case 1007:  // --no-create
		env.monitor_create = false;
		break;
	case 1008:  // --no-delete
		env.monitor_delete = false;
		break;
	case 1009:  // --no-write
		env.monitor_write = false;
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

// [Include all the other existing functions: libbpf_print_fn, sig_int, matches_exclude_patterns, 
//  matches_watch_patterns, is_editor_temp_file, is_editor_atomic_save, get_process_cwd, 
//  get_fd_path, resolve_full_path, get_event_type_str, format_flags - they remain the same]

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

static bool matches_exclude_patterns(const char *fname)
{
	for (int i = 0; i < env.exclude_pattern_count; i++) {
		if (strstr(fname, env.exclude_patterns[i]))
			return true;
	}
	return false;
}

static bool matches_watch_patterns(const char *fname)
{
	if (!env.strict_watch || env.watch_pattern_count == 0)
		return true;
	
	for (int i = 0; i < env.watch_pattern_count; i++) {
		if (strstr(fname, env.watch_patterns[i]))
			return true;
	}
	return false;
}

static bool is_editor_temp_file(const char *fname, const char *comm)
{
	const char *basename = strrchr(fname, '/');
	if (basename) {
		basename++;
	} else {
		basename = fname;
	}
	
	if (strstr(basename, ".swp") || strstr(basename, ".swo") || 
	    strstr(basename, ".un~") || strstr(basename, "~")) {
		return true;
	}
	
	if (basename[0] == '.' && strstr(basename, ".save")) {
		return true;
	}
	
	if ((basename[0] == '#' && basename[strlen(basename)-1] == '#') ||
	    (basename[0] == '.' && basename[1] == '#')) {
		return true;
	}
	
	if (strstr(basename, ".tmp-") || strstr(basename, ".code-workspace")) {
		return true;
	}
	
	if (strstr(basename, ".tmp") || strstr(basename, ".temp") ||
	    strstr(basename, ".bak") || strstr(basename, ".backup")) {
		return true;
	}
	
	size_t len = strlen(basename);
	if (len > 1 && basename[len-1] == '~') {
		return true;
	}
	
	return false;
}

static bool is_editor_atomic_save(const char *fname, const char *comm, __u32 event_type)
{
	if (event_type != EVENT_TYPE_CREATE && event_type != EVENT_TYPE_SAVE) {
		return false;
	}
	
	const char *editors[] = {
		"nano", "vim", "nvim", "vi", "emacs", "gedit", "kate", "code", 
		"atom", "sublime", "mousepad", "leafpad", "pluma", "xed"
	};
	
	bool is_editor = false;
	for (int i = 0; i < sizeof(editors)/sizeof(editors[0]); i++) {
		if (strstr(comm, editors[i])) {
			is_editor = true;
			break;
		}
	}
	
	if (!is_editor) {
		return false;
	}
	
	const char *basename = strrchr(fname, '/');
	if (basename) {
		basename++;
	} else {
		basename = fname;
	}
	
	if (strstr(basename, ".tmp") || 
	    (basename[0] == '.' && strlen(basename) > 1) ||
	    (strlen(basename) > 1 && basename[strlen(basename)-1] == '~')) {
		return true;
	}
	
	return false;
}

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

static char *resolve_full_path(pid_t pid, int dirfd, const char *fname)
{
	static char full_path[PATH_MAX];
	
	if (fname[0] == '/') {
		strncpy(full_path, fname, PATH_MAX - 1);
		full_path[PATH_MAX - 1] = '\0';
		return full_path;
	}
	
	char *dir_path = get_fd_path(pid, dirfd);
	if (!dir_path) {
		dir_path = get_process_cwd(pid);
		if (!dir_path) {
			strncpy(full_path, fname, PATH_MAX - 1);
			full_path[PATH_MAX - 1] = '\0';
			return full_path;
		}
	}
	
	size_t dir_len = strlen(dir_path);
	size_t fname_len = strlen(fname);
	
	if (dir_len + 1 + fname_len >= PATH_MAX - 1) {
		strncpy(full_path, fname, PATH_MAX - 1);
		full_path[PATH_MAX - 1] = '\0';
	} else {
		memcpy(full_path, dir_path, dir_len);
		
		if (dir_path[dir_len - 1] != '/') {
			full_path[dir_len] = '/';
			dir_len++;
		}
		
		memcpy(full_path + dir_len, fname, fname_len);
		full_path[dir_len + fname_len] = '\0';
	}
	return full_path;
}

static const char *get_event_type_str(__u32 event_type)
{
	switch (event_type) {
	case EVENT_TYPE_CREATE:
		return "CREATE";
	case EVENT_TYPE_DELETE:
		return "DELETE";
	case EVENT_TYPE_SAVE:
		return "WRITE";
	default:
		return "UNKNOWN";
	}
}

static void format_flags(int flags, char *buf, size_t buf_size)
{
	buf[0] = '\0';
	if (flags == 0) {
		strncpy(buf, "0", buf_size - 1);
		return;
	}
	
	snprintf(buf, buf_size, "%08x", flags);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct fim_event *event = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char *full_path;
	char flags_str[16];

	// Filter by event type based on user preferences
	if (event->event_type == EVENT_TYPE_CREATE && !env.monitor_create)
		return 0;
	if (event->event_type == EVENT_TYPE_DELETE && !env.monitor_delete)
		return 0;
	if (event->event_type == EVENT_TYPE_SAVE && !env.monitor_write)
		return 0;

	// Apply filters
	if (env.pid && env.pid != event->pid)
		return 0;
	if (env.uid && env.uid != event->uid)
		return 0;
	
	if (env.name_filter && !strstr(event->comm, env.name_filter))
		return 0;
	
	if (event->filename[0] == '\0')
		return 0;
	
	full_path = resolve_full_path(event->pid, event->dirfd, event->filename);
	
	if (env.exclude_editor_noise) {
		if (is_editor_temp_file(full_path, event->comm) || 
		    is_editor_atomic_save(full_path, event->comm, event->event_type)) {
			return 0;
		}
	}
	
	if (!matches_watch_patterns(full_path))
		return 0;
	
	if (env.exclude_dev_null && strcmp(full_path, "/dev/null") == 0)
		return 0;
	
	if (env.exclude_tmp_files) {
		if (strstr(full_path, ".tmp") || 
		    strstr(full_path, ".swp") ||
		    strstr(full_path, ".tmpfile") ||
		    strstr(full_path, "/.cache/") ||
		    strstr(full_path, "/tmp/") ||
		    strstr(full_path, "/var/tmp/") ||
		    (strstr(full_path, event->comm) && strstr(full_path, "/.mozilla/")))
			return 0;
	}
	
	if (matches_exclude_patterns(full_path))
		return 0;

	// NEW: Content change detection for WRITE events
	if (event->event_type == EVENT_TYPE_SAVE && env.ignore_unchanged) {
		if (!has_content_changed(full_path)) {
			if (env.verbose) {
				printf("SKIPPED: %s (no content change)\n", full_path);
			}
			return 0;  // Skip this event as content hasn't changed
		}
	}

	if (event->event_type != EVENT_TYPE_SAVE) {
		if (strstr(event->comm, "systemd") ||
		    strstr(event->comm, "kworker") ||
		    strstr(event->comm, "ksoftirqd") ||
		    strstr(event->comm, "migration") ||
		    strstr(event->comm, "rcu_") ||
		    strstr(event->comm, "watchdog"))
			return 0;
	}

	// Prepare timestamp
	if (env.timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}

	if (env.print_uid)
		printf("%-7u ", event->uid);

	if (env.show_flags && event->event_type == EVENT_TYPE_CREATE) {
		format_flags(event->flags, flags_str, sizeof(flags_str));
		printf("%-6u %-16s %-7s %-8s %04o %s\n",
		       event->pid, event->comm, get_event_type_str(event->event_type),
		       flags_str, event->mode, full_path);
	} else {
		printf("%-6u %-16s %-7s %s\n",
		       event->pid, event->comm, get_event_type_str(event->event_type),
		       full_path);
	}
	
	return 0;
}

static void print_header()
{
	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_uid)
		printf("%-7s ", "UID");
	
	if (env.show_flags) {
		printf("%-6s %-16s %-7s %-8s %-4s %s\n", 
		       "PID", "COMM", "EVENT", "FLAGS", "MODE", "PATH");
	} else {
		printf("%-6s %-16s %-7s %s\n", 
		       "PID", "COMM", "EVENT", "PATH");
	}
}

static void print_configuration()
{
	printf("Enhanced File Integrity Monitor Configuration:\n");
	
	// Event types being monitored
	printf("Monitoring: ");
	int event_count = 0;
	if (env.monitor_create) {
		printf("CREATE");
		event_count++;
	}
	if (env.monitor_delete) {
		if (event_count > 0) printf(", ");
		printf("DELETE");
		event_count++;
	}
	if (env.monitor_write) {
		if (event_count > 0) printf(", ");
		printf("WRITE");
		event_count++;
	}
	printf(" events\n");
	
	// NEW: Content awareness status
	if (env.content_aware) {
		printf("Content-aware monitoring: ENABLED");
		if (env.ignore_unchanged) {
			printf(" (ignoring unchanged saves)");
		} else {
			printf(" (showing all saves)");
		}
		printf("\n");
	} else {
		printf("Content-aware monitoring: DISABLED (faster but less accurate)\n");
	}
	
	if (env.exclude_editor_noise) {
		printf("Editor noise filtering: ENABLED\n");
	} else {
		printf("Editor noise filtering: DISABLED\n");
	}
	
	if (env.strict_watch) {
		printf("Strict watching mode enabled. Monitoring only paths containing:\n");
		for (int i = 0; i < env.watch_pattern_count; i++) {
			printf("  - %s\n", env.watch_patterns[i]);
		}
	} else {
		printf("Monitoring all file operations");
		if (env.exclude_pattern_count > 0) {
			printf(" (excluding patterns: ");
			for (int i = 0; i < env.exclude_pattern_count; i++) {
				printf("%s%s", env.exclude_patterns[i], 
				       (i < env.exclude_pattern_count - 1) ? ", " : "");
			}
			printf(")");
		}
		printf("\n");
	}
	
	if (env.pid)
		printf("PID filter: %u\n", env.pid);
	if (env.uid)
		printf("UID filter: %u\n", env.uid);
	if (env.name_filter)
		printf("Process name filter: %s\n", env.name_filter);
	if (env.show_flags)
		printf("Showing detailed flags and mode for create events\n");
	
	printf("\n");
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
	ring_buffer__free(rb);
	fim_bpf__destroy(skel);
	return err;
}

