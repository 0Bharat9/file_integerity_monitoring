#include "Watcher.hpp"
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <poll.h>

Watcher::Watcher() {
    inotifyFd = inotify_init1(IN_NONBLOCK);
    if (inotifyFd == -1) {
        perror("inotify_init1");
        exit(1);
    }
}

Watcher::~Watcher() {
    close(inotifyFd);
}

void Watcher::addWatchRecursive(const std::string& path) {
    if (pathToWd.find(path) == pathToWd.end()) {
        int wd = inotify_add_watch(inotifyFd, path.c_str(),
                                   IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO);
        if (wd != -1) {
            wdToPath[wd] = path;
            pathToWd[path] = wd;
            std::cout << "Watching: " << path << "\n";
        }
    }

    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        if (entry.is_directory()) {
            std::string dirPath = entry.path().string();
            if (pathToWd.find(dirPath) == pathToWd.end()) {
                int wd = inotify_add_watch(inotifyFd, dirPath.c_str(),
                                           IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO);
                if (wd != -1) {
                    wdToPath[wd] = dirPath;
                    pathToWd[dirPath] = wd;
                    std::cout << "Watching: " << dirPath << "\n";
                }
            }
        }
    }
}

void Watcher::printEvent(const struct inotify_event* event) {
    std::string dir = wdToPath[event->wd];
    std::string file = event->len ? event->name : "";
    std::string fullPath = dir + "/" + file;

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

    // If new directory is created, watch it
    if ((event->mask & IN_CREATE || event->mask & IN_MOVED_TO) && event->mask & IN_ISDIR) {
        addWatchRecursive(fullPath);
    }
}

void Watcher::watchDirectoryRecursive(const std::string& path) {
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

        for (char* ptr = buffer; ptr < buffer + length;) {
            struct inotify_event* event = (struct inotify_event*)ptr;
            printEvent(event);
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }
}

