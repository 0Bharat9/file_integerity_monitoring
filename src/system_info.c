#include "system_info.h"

// Define the global variables
char system_hostname[256] = "unknown";
char system_ip[16] = "127.0.0.1";
char current_user[256] = "unknown";

// Initialize system information - REMOVED static keyword
void init_system_info() {
	// Get hostname
	if (gethostname(system_hostname, sizeof(system_hostname)) != 0) {
		strncpy(system_hostname, "unknown", sizeof(system_hostname));
	}
	
	// Get current user
	struct passwd *pw = getpwuid(getuid());
	if (pw) {
		strncpy(current_user, pw->pw_name, sizeof(current_user));
	} else {
		strncpy(current_user, "unknown", sizeof(current_user));
	}
	
	// Get system IP address
	struct ifaddrs *ifaddrs_ptr = NULL;
	strcpy(system_ip, "127.0.0.1"); // default
	
	if (getifaddrs(&ifaddrs_ptr) == 0) {
		struct ifaddrs *ifa;
		for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
				// Skip loopback interface
				if (strcmp(ifa->ifa_name, "lo") == 0) continue;
				
				struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
				inet_ntop(AF_INET, &(sa->sin_addr), system_ip, INET_ADDRSTRLEN);
				break;
			}
		}
		freeifaddrs(ifaddrs_ptr);
	}
}
