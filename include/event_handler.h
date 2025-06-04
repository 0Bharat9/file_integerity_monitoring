#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include "fim_userspace.h"

// Event handling functions
int handle_event(void *ctx, void *data, size_t data_sz);
static const char *get_event_type_str(__u32 event_type);
static void format_flags(int flags, char *buf, size_t buf_size);

// Filtering functions
static bool matches_exclude_patterns(const char *fname);
static bool matches_watch_patterns(const char *fname);
static bool is_editor_temp_file(const char *fname, const char *comm);
static bool is_editor_atomic_save(const char *fname, const char *comm, __u32 event_type);

// Display functions
void print_header(void);
void print_configuration(void);

#endif /* EVENT_HANDLER_H */
