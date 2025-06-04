#ifndef JSON_LOGGER_H
#define JSON_LOGGER_H

#include "fim_userspace.h"

// Logging functions - REMOVED static keyword
bool init_logging();
void cleanup_logging();
void log_event_json(const struct fim_event *event, const char *full_path);

// Utility functions - REMOVED static keyword where needed for external use
static const char *get_file_extension(const char *filename);
static bool get_file_owner(const char *filepath, char *owner_buf, size_t buf_size);
static void get_file_permissions(const char *filepath, char *perm_buf, size_t buf_size);
static long get_file_size(const char *filepath);
static const char* get_file_event_type(__u32 event_type);

#endif /* JSON_LOGGER_H */

