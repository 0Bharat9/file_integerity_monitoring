#ifndef WATCHER_HPP
#define WATCHER_HPP

#include "Logger.hpp"
#include <filesystem>
#include <limits.h>
#include <map>
#include <string>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unordered_map>

#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + NAME_MAX + 1))

namespace fs = std::filesystem;

class Watcher {
public:
  Watcher(Logger *logger);
  ~Watcher();

  void watchDirectoryRecursive(const std::string &path);
  void processEvents();

private:
  void addWatchRecursive(const std::string &path);
  void printEvent(const struct inotify_event *event);

  Logger *logger;
  int inotifyFd;
  std::map<int, std::string> wdToPath;
  std::map<std::string, int> pathToWd;
  std::unordered_map<std::string, struct stat> pathToStat;
};

#endif // WATCHER_HPP
