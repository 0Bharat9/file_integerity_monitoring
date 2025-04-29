#include <iostream>
#include "Watcher.hpp"
#include "Logger.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <directory_to_watch>\n";
        return 1;
    }

    const std::string rootPath = argv[1];
    
    Logger logger("fim.log");
    Watcher watcher(&logger);

    watcher.watchDirectoryRecursive(rootPath);
    watcher.processEvents();

    return 0;
}

