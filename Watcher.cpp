#include "Watcher.hpp"
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

/*void Watcher::printEvent(const struct inotify_event *event) {
  std::string dir = wdToPath[event->wd];
  std::string file = event->len ? event->name : "";
  std::string fullPath = dir + "/" + file;

  struct stat sb{};
  bool statAvailable = false;

  // Skip temporary files created during package operations
  if (file.ends_with(".dpkg-new")) {
    return;
  }

  if ((event->mask & IN_DELETE)) {
    // For DELETE, try to get cached stat
    auto it = pathToStat.find(fullPath);
    if (it != pathToStat.end()) {
      sb = it->second;
      statAvailable = true;
    }
  } else {
    // Retry stat() up to 5 times if needed
    const int maxRetries = 5;
    int retries = 0;
    while (retries < maxRetries) {
      if (stat(fullPath.c_str(), &sb) == 0) {
        pathToStat[fullPath] = sb;
        statAvailable = true;
        break;
      }
      usleep(10000); // wait 10 ms
      retries++;
    }

    if (!statAvailable) {
      std::cout << "File deleted before stat could run: " << fullPath << "\n";
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

  // If new directory is created or moved in, add a watch
  if ((event->mask & IN_CREATE || event->mask & IN_MOVED_TO) &&
      event->mask & IN_ISDIR) {
    addWatchRecursive(fullPath);
  }
}*/

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
