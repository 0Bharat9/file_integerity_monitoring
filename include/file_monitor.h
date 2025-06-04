#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include "fim_userspace.h"

// File state structure
struct file_state {
    char path[PATH_MAX];
    unsigned char hash[HASH_SIZE];
    time_t last_modified;
    struct file_state *next;
};

// File monitoring functions - Remove static keywords for external use
bool has_content_changed(const char *filepath);
void cleanup_file_cache(void);

#endif /* FILE_MONITOR_H */

