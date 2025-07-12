#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <mntent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "../../lib/uWebSockets/src/App.h"
#include "share.h"
#include "vaultClient.h"

class ServerUtils {
 public:
  static ServerUtils& instance();

  SessionInfo generateSessionToken();

  static bool startsWith(const std::string& value, const std::string& start);
  static bool endsWith(const std::string& value, const std::string& ending);

  static bool isAuthorized(uWS::HttpRequest* req);
  static bool checkInternal(uWS::HttpRequest* req);
  static bool checkOrigin(uWS::HttpRequest* req);

  static std::string getExecutablePath();

  static std::vector<char> readPassword(const std::string& prompt);

  static bool isAlreadyMounted(const std::string& path);

  static std::string readFile(const std::string& path);

  void cleanup(int signum);

  void secureWipeDirectory(const std::string& dirPath);

  std::string randomDigits(int length);

 private:
  ServerUtils();
  ServerUtils(const ServerUtils&) = delete;
  ServerUtils& operator=(const ServerUtils&) = delete;

  static std::unique_ptr<ServerUtils> instance_;
};
