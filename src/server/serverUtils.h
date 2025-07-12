#pragma once

#include "../../lib/uWebSockets/src/App.h"

class ServerUtils {
 public:
  static ServerUtils& instance();

  std::string generateSessionToken();

  static bool startsWith(const std::string& value, const std::string& start);
  static bool endsWith(const std::string& value, const std::string& ending);

  static bool isAuthorized(uWS::HttpRequest* req);
  static bool checkInternal(uWS::HttpRequest* req);
  static bool checkOrigin(uWS::HttpRequest* req);

  static std::string getExecutablePath();

  static std::string readPassword(const std::string& prompt);

  static bool isAlreadyMounted(const std::string& path);

  static std::string readFile(const std::string& path);

 private:
  ServerUtils();

  static std::unique_ptr<ServerUtils> instance_;
};
