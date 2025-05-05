#include "Watcher.hpp"
#include <cstring>
#include <iostream>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>

Watcher::Watcher(Logger *log) : logger(log) {
  inotifyFd = inotify_init1(IN_NONBLOCK);
  if (inotifyFd == -1) {
    perror("inotify_init1");
    exit(1);
  }
}

Watcher::~Watcher() { close(inotifyFd); }

bool Watcher::isWatchedPathValid(const std::string &path) {
  auto it = pathToWd.find(path);
  if (it == pathToWd.end()) return false;
  int wd = it->second;
  return wdToPath.find(wd) != wdToPath.end();
}

void Watcher::addWatchRecursive(const std::string &path) {
  if (!isWatchedPathValid(path)) {
    int wd = inotify_add_watch(inotifyFd, path.c_str(),
                               IN_CREATE | IN_DELETE | IN_MODIFY |
                                   IN_MOVED_FROM | IN_MOVED_TO |
                                   IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd != -1) {
      wdToPath[wd] = path;
      pathToWd[path] = wd;
      std::cout << "Watching: " << path << "\n";
    }
  }

  try {
    for (const auto &entry : fs::recursive_directory_iterator(path)) {
      if (entry.is_directory()) {
        std::string dirPath = entry.path().string();
        if (!isWatchedPathValid(dirPath)) {
          int wd = inotify_add_watch(inotifyFd, dirPath.c_str(),
                                     IN_CREATE | IN_DELETE | IN_MODIFY |
                                         IN_MOVED_FROM | IN_MOVED_TO |
                                         IN_DELETE_SELF | IN_MOVE_SELF);
          if (wd != -1) {
            wdToPath[wd] = dirPath;
            pathToWd[dirPath] = wd;
            std::cout << "Watching: " << dirPath << "\n";
          }
        }
      } else {
        const std::string filePath = entry.path().string();
        struct stat sb;
        if (stat(filePath.c_str(), &sb) == 0) {
          pathToStat[filePath] = sb;
        }
      }
    }
  } catch (const fs::filesystem_error &e) {
    std::cerr << "Filesystem error: " << e.what() << "\n";
  }
}

void Watcher::printEvent(const struct inotify_event *event) {
  std::string dir = wdToPath[event->wd];
  std::string file = event->len ? event->name : "";
  std::string fullPath = dir + (file.empty() ? "" : "/" + file);

  // Handle removed watch
  if (event->mask & IN_IGNORED || event->mask & IN_DELETE_SELF) {
    std::cout << "[UNWATCH] " << dir << "\n";
    pathToWd.erase(dir);
    wdToPath.erase(event->wd);
    return;
  }

  struct stat sb{};
  bool statAvailable = false;

  if ((event->mask & IN_DELETE)) {
    auto it = pathToStat.find(fullPath);
    if (it != pathToStat.end()) {
      sb = it->second;
      statAvailable = true;
    }
  } else {
    if (stat(fullPath.c_str(), &sb) == 0) {
      pathToStat[fullPath] = sb;
      statAvailable = true;
    }
  }

  if (event->mask & IN_CREATE) {
    std::cout << "[CREATE] " << fullPath << "\n";
  }
  if (event->mask & IN_DELETE) {
    std::cout << "[DELETE] " << fullPath << "\n";
  }
  if (event->mask & IN_MODIFY) {
    std::cout << "[MODIFY] " << fullPath << "\n";
  }
  if (event->mask & IN_MOVED_FROM) {
    std::cout << "[MOVED_FROM] " << fullPath << "\n";
  }
  if (event->mask & IN_MOVED_TO) {
    std::cout << "[MOVED_TO] " << fullPath << "\n";
  }

  if (statAvailable) {
    logger->logEvent((event->mask & IN_CREATE)   ? "create"
                     : (event->mask & IN_DELETE) ? "delete"
                     : (event->mask & IN_MODIFY) ? "modify"
                                                 : "other",
                     fullPath, "", getpid(), &sb);
  }

  // Add watch if new directory created or moved in
  if ((event->mask & IN_CREATE || event->mask & IN_MOVED_TO) &&
      (event->mask & IN_ISDIR)) {
    addWatchRecursive(fullPath);
  }
}

void Watcher::watchDirectoryRecursive(const std::string &path) {
  addWatchRecursive(path);
}

void Watcher::processEvents() {
  char buffer[EVENT_BUF_LEN];

  while (true) {
    ssize_t length = read(inotifyFd, buffer, EVENT_BUF_LEN);
    if (length < 0) {
      if (errno == EAGAIN) {
        usleep(500 * 1000); // wait a bit
        continue;
      } else {
        perror("read");
        break;
      }
    }

    for (char *ptr = buffer; ptr < buffer + length;) {
      struct inotify_event *event = (struct inotify_event *)ptr;
      printEvent(event);
      ptr += sizeof(struct inotify_event) + event->len;
    }
  }
}

/*#include "Watcher.hpp"
#include <cstring>
#include <iostream>
#include <poll.h>
#include <unistd.h>

Watcher::Watcher(Logger *log) : logger(log) {
  inotifyFd = inotify_init1(IN_NONBLOCK);
  if (inotifyFd == -1) {
    perror("inotify_init1");
    exit(1);
  }
}

Watcher::~Watcher() { close(inotifyFd); }

void Watcher::addWatchRecursive(const std::string &path) {
  if (pathToWd.find(path) == pathToWd.end()) {
    int wd = inotify_add_watch(inotifyFd, path.c_str(),
                               IN_CREATE | IN_DELETE | IN_MODIFY |
                                   IN_MOVED_FROM | IN_MOVED_TO);
    if (wd != -1) {
      wdToPath[wd] = path;
      pathToWd[path] = wd;
      std::cout << "Watching: " << path << "\n";
    }
  }

  try {
    for (const auto &entry : fs::recursive_directory_iterator(path)) {
      if (entry.is_directory()) {
        std::string dirPath = entry.path().string();
        if (pathToWd.find(dirPath) == pathToWd.end()) {
          int wd = inotify_add_watch(inotifyFd, dirPath.c_str(),
                                     IN_CREATE | IN_DELETE | IN_MODIFY |
                                         IN_MOVED_FROM | IN_MOVED_TO);
          if (wd != -1) {
            wdToPath[wd] = dirPath;
            pathToWd[dirPath] = wd;
            std::cout << "Watching: " << dirPath << "\n";
          }
        }
      } else {
        const std::string filePath = entry.path().string();
        struct stat sb;
        if (stat(filePath.c_str(), &sb) == 0) {
          pathToStat[filePath] = sb;
        }
      }
    }
  } catch (const fs::filesystem_error &e) {
    std::cerr << "Filesystem error: " << e.what() << "\n";
  }
}

void Watcher::printEvent(const struct inotify_event *event) {
  std::string dir = wdToPath[event->wd];
  std::string file = event->len ? event->name : "";
  std::string fullPath = dir + "/" + file;

  struct stat sb{};
  bool statAvailable = false;

  if ((event->mask & IN_DELETE)) {
    // For DELETE, try to get cached stat
    auto it = pathToStat.find(fullPath);
    if (it != pathToStat.end()) {
      sb = it->second;
      statAvailable = true;
    }
  } else {
    if (stat(fullPath.c_str(), &sb) == 0) {
      pathToStat[fullPath] = sb;
      statAvailable = true;
    }
  }

  if (event->mask & IN_CREATE) {
    std::cout << "[CREATE] " << fullPath << "\n";
    // logger->logEvent("create", fullPath);
  }
  if (event->mask & IN_DELETE) {
    std::cout << "[DELETE] " << fullPath << "\n";
    // logger->logEvent("delete", fullPath);
  }
  if (event->mask & IN_MODIFY) {
    std::cout << "[MODIFY] " << fullPath << "\n";
    // logger->logEvent("modify", fullPath);
  }
  if (event->mask & IN_MOVED_FROM) {
    std::cout << "[MOVED_FROM] " << fullPath << "\n";
  }
  if (event->mask & IN_MOVED_TO) {
    std::cout << "[MOVED_TO] " << fullPath << "\n";
  }

  if (statAvailable) {
    logger->logEvent((event->mask & IN_CREATE)   ? "create"
                     : (event->mask & IN_DELETE) ? "delete"
                     : (event->mask & IN_MODIFY) ? "modify"
                                                 : "other",
                     fullPath, "", getpid(), &sb);
  }
  // If new directory is created, watch it
  if ((event->mask & IN_CREATE || event->mask & IN_MOVED_TO) &&
      event->mask & IN_ISDIR) {
    addWatchRecursive(fullPath);
  }
}

void Watcher::watchDirectoryRecursive(const std::string &path) {
  addWatchRecursive(path);
}

void Watcher::processEvents() {
  char buffer[EVENT_BUF_LEN];

  while (true) {
    ssize_t length = read(inotifyFd, buffer, EVENT_BUF_LEN);
    if (length < 0) {
      if (errno == EAGAIN) {
        usleep(500 * 1000); // wait a bit
        continue;
      } else {
        perror("read");
        break;
      }
    }

    for (char *ptr = buffer; ptr < buffer + length;) {
      struct inotify_event *event = (struct inotify_event *)ptr;
      printEvent(event);
      ptr += sizeof(struct inotify_event) + event->len;
    }
  }
}*/
