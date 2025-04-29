#include "Logger.hpp"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>

using json = nlohmann::json;

Logger::Logger(const std::string& logPath) : logFilePath(logPath) {}

void Logger::logEvent(const std::string& action, const std::string& filePath, const std::string& process, int pid) {
    struct stat sb{};
    if (stat(filePath.c_str(), &sb) != 0) {
        std::cerr << "Failed to stat: " << filePath << "\n";
        return;
    }

    std::string user = getUsername(sb.st_uid);
    std::string perms = getPermissions(sb.st_mode);
    std::string hostname = getHostname();
    std::string ip = getIPAddress();

    json j;
    j["timestamp"] = getTimestamp();
    j["user"] = user;
    j["account"] = user;
    j["asset"] = hostname;
    j["asset_address"] = ip;
    j["asset_os_family"] = "linux";
    j["file_event"] = action;
    j["file_path"] = filePath;

    std::string name = filePath.substr(filePath.find_last_of("/") + 1);
    std::string ext = name.find('.') != std::string::npos ? name.substr(name.find_last_of(".") + 1) : "";
    
    j["file_name"] = name;
    j["file_extension"] = ext;
    j["file_size"] = sb.st_size;
    j["file_owner"] = user;
    j["file_permissions"] = perms;
    j["process"] = process;
    j["process_id"] = std::to_string(pid);
    j["process_user"] = user;
    j["process_path"] = process;


    appendToFile(j.dump());
}

void Logger::appendToFile(const std::string& line) {
    std::ofstream out(logFilePath, std::ios::app);
    out << line << std::endl;
}

std::string Logger::getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto itt = std::chrono::system_clock::to_time_t(now);
    auto tm = *gmtime(&itt);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%FT%T.000Z");
    return oss.str();
}

std::string Logger::getUsername(uid_t uid) {
    struct passwd* pw = getpwuid(uid);
    return pw ? std::string(pw->pw_name) : "unknown";
}

std::string Logger::getPermissions(mode_t mode) {
    std::string perms = "---------";
    perms[0] = (mode & S_IRUSR) ? 'r' : '-';
    perms[1] = (mode & S_IWUSR) ? 'w' : '-';
    perms[2] = (mode & S_IXUSR) ? 'x' : '-';
    perms[3] = (mode & S_IRGRP) ? 'r' : '-';
    perms[4] = (mode & S_IWGRP) ? 'w' : '-';
    perms[5] = (mode & S_IXGRP) ? 'x' : '-';
    perms[6] = (mode & S_IROTH) ? 'r' : '-';
    perms[7] = (mode & S_IWOTH) ? 'w' : '-';
    perms[8] = (mode & S_IXOTH) ? 'x' : '-';
    return perms;
}

std::string Logger::getHostname() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    return std::string(hostname);
}

std::string Logger::getIPAddress() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    std::string result = "127.0.0.1";

    if (getifaddrs(&ifaddr) == -1)
        return result;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0) {
            result = host;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return result;
}

