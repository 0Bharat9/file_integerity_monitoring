#include "path_utils.h"

// REMOVED static keyword from all functions
char *get_process_cwd(pid_t pid)
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

char *get_fd_path(pid_t pid, int fd)
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

char *resolve_full_path(pid_t pid, int dirfd, const char *fname)
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

// Get process path
bool get_process_path(pid_t pid, char *path_buf, size_t buf_size) {
	char proc_path[64];
	snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
	
	ssize_t len = readlink(proc_path, path_buf, buf_size - 1);
	if (len != -1) {
		path_buf[len] = '\0';
		return true;
	}
	
	strncpy(path_buf, "unknown", buf_size);
	return false;
}
