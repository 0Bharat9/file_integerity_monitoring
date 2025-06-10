#include "event_handler.h"
#include "file_monitor.h"
#include "json_logger.h"
#include "path_utils.h"
#include <errno.h>

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

static const char *get_event_type_str(__u32 event_type)
{
	switch (event_type) {
	case EVENT_TYPE_CREATE:
		return "CREATE";
	case EVENT_TYPE_DELETE:
		return "DELETE";
	case EVENT_TYPE_SAVE:
		return "WRITE";
  case EVENT_TYPE_RENAME:
    return "MOVE/RENAME";
  case EVENT_TYPE_SYMLINK:
    return "SYMLINK";
    case EVENT_TYPE_TIMESTAMP:
    return "TIME_CHANGE";
  default:
		return "UNKNOWN";
	}
}

void format_flags(int flags, char *buf, size_t buf_size)
{
	buf[0] = '\0';
	if (flags == 0) {
		strncpy(buf, "0", buf_size - 1);
		return;
	}
	
	snprintf(buf, buf_size, "%08x", flags);
}

void print_header()
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

void print_configuration()
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
  if (env.monitor_rename) {
		if (event_count > 0) printf(", ");
		printf("RENAME");
		event_count++;
	}
  if (env.monitor_symlink) {
		if (event_count > 0) printf(", ");
		printf("SYMLINK");
		event_count++;
	}
	if (env.monitor_time_change) {
		if (event_count > 0) printf(", ");
		printf("TIME_CHANGE");
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

void print_stats(int stats_fd) {
    uint32_t key;
    uint64_t value;
    
    printf("=== BPF FIM Stats ===\n");
    
    key = 0; // STAT_DROPPED_EVENTS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Dropped events: %llu\n", value);
    }
    
    key = 1; // STAT_TOTAL_EVENTS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Total events: %llu\n", value);
    }
    
    key = 2; // STAT_CREATE_EVENTS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Create events: %llu\n", value);
    }
    
    key = 3; // STAT_SAVE_EVENTS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Save events: %llu\n", value);
    }
    
    key = 4; // STAT_DELETE_EVENTS - ADD THIS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Delete events: %llu\n", value);
    }
    
    key = 5; // STAT_CREATE_EVENTS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Rename events: %llu\n", value);
    }
    
    key = 6; // STAT_SAVE_EVENTS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Symlink events: %llu\n", value);
    }
    
    key = 7; // STAT_DELETE_EVENTS - ADD THIS
    if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
        printf("Timestamp_change events: %llu\n", value);
    }
    
}

int handle_event(void *ctx, void *data, size_t data_sz)
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
  if (event->event_type == EVENT_TYPE_RENAME && !env.monitor_rename)
		return 0;
	if (event->event_type == EVENT_TYPE_SYMLINK && !env.monitor_symlink)
		return 0;
	if (event->event_type == EVENT_TYPE_TIMESTAMP && !env.monitor_time_change)
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
  if (event->event_type == EVENT_TYPE_CREATE) {
    if (!is_new_file_creation(full_path)) {
        if (env.verbose) {
            printf("SKIPPED CREATE: %s (file already exists)\n", full_path);
        }
        return 0;  // Skip this CREATE event
    }
  }

  if(event->event_type == EVENT_TYPE_DELETE){
    struct file_state *state = get_file_state(full_path);
    if (state) state->file_exists = false;
  }

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
  
  log_event_json(event, full_path);
	
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
