#include "json_logger.h"
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

static char system_hostname[256] = "unknown";
static char system_ip[64] = "127.0.0.1";
static bool system_info_initialized = false;

static void initialize_system_info_internal(void) {
    if (system_info_initialized) return;
    
    // Get hostname
    if (gethostname(system_hostname, sizeof(system_hostname)) != 0) {
        strncpy(system_hostname, "unknown", sizeof(system_hostname) - 1);
    }
    system_hostname[sizeof(system_hostname) - 1] = '\0';
    
    // Simple IP detection - get first non-loopback IP
    struct ifaddrs *ifaddrs_ptr = NULL;
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs *ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
                char *ip = inet_ntoa(addr_in->sin_addr);
                if (ip && strcmp(ip, "127.0.0.1") != 0) {
                    strncpy(system_ip, ip, sizeof(system_ip) - 1);
                    system_ip[sizeof(system_ip) - 1] = '\0';
                    break;
                }
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }
    
    system_info_initialized = true;
}

// Initialize logging
bool init_logging() {
	if (!env.enable_logging) {
		return true; // Success if logging disabled
	}
	
	log_file = fopen(LOG_FILE_PATH, "a");
	if (!log_file) {
		fprintf(stderr, "Warning: Cannot open log file %s: %s\n", 
		        LOG_FILE_PATH, strerror(errno));
		fprintf(stderr, "Continuing without logging...\n");
		env.enable_logging = false;
		return false;
	}
	
	// Set line buffering for immediate writes
	setvbuf(log_file, NULL, _IOLBF, 0);
	return true;
}


// Map event type to string
static const char* get_file_event_type(__u32 event_type) {
	switch (event_type) {
		case EVENT_TYPE_CREATE:
			return "create";
		case EVENT_TYPE_DELETE:
			return "delete";
		case EVENT_TYPE_SAVE:
			return "modify";
		default:
			return "other";
	}
}

// Log event to JSON file - REMOVED static
void log_event_json(const struct fim_event *event, const char *full_path) {
	initialize_system_info_internal();
    if (!env.enable_logging || !log_file) {
		return;
	}
	
	// Get current timestamp in ISO format
	time_t now;
	time(&now);
	struct tm *utc_tm = gmtime(&now);
	char timestamp[32];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S.000Z", utc_tm);
	
	// Get file information
	char file_owner[256];
	char file_permissions[16];
	char process_path[PATH_MAX];
	long file_size;
	
	get_file_owner(full_path, file_owner, sizeof(file_owner));
	get_file_permissions(full_path, file_permissions, sizeof(file_permissions));
	get_process_path(event->pid, process_path, sizeof(process_path));
	file_size = get_file_size(full_path);
	
	// Get process user
	char process_user[256];
    struct passwd *pw_local = getpwuid(getuid());
    if (pw_local != NULL) {
        strncpy(process_user, pw_local->pw_name, sizeof(process_user) - 1);
        process_user[sizeof(process_user) - 1] = '\0';
    } else {
        strncpy(process_user, "unknown", sizeof(process_user) - 1);
        process_user[sizeof(process_user) - 1] = '\0';
    }
	
	// Get file basename and extension
	const char *file_basename = strrchr(full_path, '/');
	if (file_basename) {
		file_basename++;
	} else {
		file_basename = full_path;
	}
	
	const char *file_extension = get_file_extension(file_basename);
	
	// Escape strings for JSON
	char escaped_path[PATH_MAX * 2];
	char escaped_filename[512];
	char escaped_comm[64];
	char escaped_process_path[PATH_MAX * 2];
	char escaped_owner[512];
	char escaped_user[512];
	
	escape_json_string(full_path, escaped_path, sizeof(escaped_path));
	escape_json_string(file_basename, escaped_filename, sizeof(escaped_filename));
	escape_json_string(event->comm, escaped_comm, sizeof(escaped_comm));
	escape_json_string(process_path, escaped_process_path, sizeof(escaped_process_path));
	escape_json_string(file_owner, escaped_owner, sizeof(escaped_owner));
	escape_json_string(process_user, escaped_user, sizeof(escaped_user));
	
	// Write JSON log entry
	fprintf(log_file, 
		"{"
		"\"account\":\"%s\","
		"\"asset\":\"%s\","
		"\"asset_address\":\"%s\","
		"\"asset_os_family\":\"linux\","
		"\"file_event\":\"%s\","
		"\"file_extension\":\"%s\","
		"\"file_name\":\"%s\","
		"\"file_owner\":\"%s\","
		"\"file_path\":\"%s\","
		"\"file_permissions\":\"%s\","
		"\"file_size\":%ld,"
		"\"process\":\"%s\","
		"\"process_id\":\"%u\","
		"\"process_path\":\"%s\","
		"\"process_user\":\"%s\","
		"\"timestamp\":\"%s\","
		"\"user\":\"%s\""
		"}\n",
		escaped_user,                    // account
		system_hostname,                 // asset  
		system_ip,                       // asset_address
		get_file_event_type(event->event_type), // file_event
		file_extension,                  // file_extension
		escaped_filename,                // file_name
		escaped_owner,                   // file_owner
		escaped_path,                    // file_path
		file_permissions,                // file_permissions
		file_size,                       // file_size
		escaped_comm,                    // process
		event->pid,                      // process_id
		escaped_process_path,            // process_path
		escaped_user,                    // process_user
		timestamp,                       // timestamp
		escaped_user                     // user
	);
	
	fflush(log_file);
}


// Escape JSON strings
void escape_json_string(const char *src, char *dst, size_t dst_size) {
	size_t src_len = strlen(src);
	size_t dst_idx = 0;
	
	for (size_t i = 0; i < src_len && dst_idx < dst_size - 2; i++) {
		char c = src[i];
		if (c == '"' || c == '\\') {
			if (dst_idx < dst_size - 3) {
				dst[dst_idx++] = '\\';
				dst[dst_idx++] = c;
			}
		} else if (c == '\n') {
			if (dst_idx < dst_size - 3) {
				dst[dst_idx++] = '\\';
				dst[dst_idx++] = 'n';
			}
		} else if (c == '\r') {
			if (dst_idx < dst_size - 3) {
				dst[dst_idx++] = '\\';
				dst[dst_idx++] = 'r';
			}
		} else if (c == '\t') {
			if (dst_idx < dst_size - 3) {
				dst[dst_idx++] = '\\';
				dst[dst_idx++] = 't';
			}
		} else if (c >= 32 && c <= 126) { // printable ASCII
			dst[dst_idx++] = c;
		}
		// Skip other control characters
	}
	dst[dst_idx] = '\0';
}


// Get file extension - REMOVED static
static const char* get_file_extension(const char *filename) {
	const char *dot = strrchr(filename, '.');
	if (!dot || dot == filename) {
		return "";
	}
	return dot + 1;
}

// Get file owner name - REMOVED static
static bool get_file_owner(const char *filepath, char *owner_buf, size_t buf_size) {
	struct stat st;
	if (stat(filepath, &st) != 0) {
		strncpy(owner_buf, "unknown", buf_size);
		return false;
	}
	
	struct passwd *pw = getpwuid(st.st_uid);
	if (pw) {
		strncpy(owner_buf, pw->pw_name, buf_size);
	} else {
		snprintf(owner_buf, buf_size, "%d", st.st_uid);
	}
	return true;
}

// Get file permissions string
static void get_file_permissions(const char *filepath, char *perm_buf, size_t buf_size) {
	struct stat st;
	if (stat(filepath, &st) != 0) {
		strncpy(perm_buf, "unknown", buf_size);
		return;
	}
	
	mode_t mode = st.st_mode;
	snprintf(perm_buf, buf_size, "%c%c%c%c%c%c%c%c%c",
		(mode & S_IRUSR) ? 'r' : '-',
		(mode & S_IWUSR) ? 'w' : '-',
		(mode & S_IXUSR) ? 'x' : '-',
		(mode & S_IRGRP) ? 'r' : '-',
		(mode & S_IWGRP) ? 'w' : '-',
		(mode & S_IXGRP) ? 'x' : '-',
		(mode & S_IROTH) ? 'r' : '-',
		(mode & S_IWOTH) ? 'w' : '-',
		(mode & S_IXOTH) ? 'x' : '-');
}

// Get file size static
static long get_file_size(const char *filepath) {
	struct stat st;
	if (stat(filepath, &st) == 0) {
		return st.st_size;
	}
	return -1;
}

void cleanup_logging() {
	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}
}

