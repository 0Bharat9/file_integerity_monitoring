#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include "fim_userspace.h"

// File state structure
struct file_state {
    char path[PATH_MAX];
    unsigned char hash[HASH_SIZE];
    time_t last_modified;
    bool file_exists;
    struct file_state *next;
};

// File monitoring functions
bool has_content_changed(const char *filepath);
void cleanup_file_cache(void);
bool is_new_file_creation(const char *filepath);
struct file_state *get_file_state(const char *path);

#endif /* FILE_MONITOR_H */

