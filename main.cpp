#include <iostream>
#include "Watcher.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <directory_to_watch>\n";
        return 1;
    }

    const std::string rootPath = argv[1];

    Watcher watcher;
    watcher.watchDirectoryRecursive(rootPath);
    watcher.processEvents();

    return 0;
}

