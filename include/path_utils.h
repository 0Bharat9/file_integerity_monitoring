#ifndef PATH_UTILS_H
#define PATH_UTILS_H

#include "fim_userspace.h"

// Path resolution functions
char *get_process_cwd(pid_t pid);
char *get_fd_path(pid_t pid, int fd);
char *resolve_full_path(pid_t pid, int dirfd, const char *fname);
bool get_process_path(pid_t pid, char *path_buf, size_t buf_size);


#endif /* PATH_UTILS_H */

