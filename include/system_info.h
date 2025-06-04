#ifndef SYSTEM_INFO_H
#define SYSTEM_INFO_H

#include "fim_userspace.h"
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>

// System information
extern char system_hostname[256];
extern char system_ip[16];  // INET_ADDRSTRLEN
extern char current_user[256];

// System info functions - REMOVED static keyword
void init_system_info(void);

#endif /* SYSTEM_INFO_H */

