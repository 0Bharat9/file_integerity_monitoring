#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <nlohmann/json.hpp>
#include <string>

class Logger {
public:
  Logger(const std::string &logPath);
  // void logEvent(const std::string& action, const std::string& filePath, const
  // std::string& process = "unknown", int pid = -1);
  void logEvent(const std::string &action, const std::string &filePath,
                const std::string &process = "", int pid = 0,
                const struct stat *preStat = nullptr);

private:
  std::string logFilePath;

  std::string getTimestamp();
  std::string getUsername(uid_t uid);
  std::string getPermissions(mode_t mode);
  std::string getHostname();
  std::string getIPAddress();
  void appendToFile(const std::string &line);
};

#endif // LOGGER_HPP
