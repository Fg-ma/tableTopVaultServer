#include "serverUtils.h"

#include <mntent.h>
#include <termios.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>

#include "share.h"
#include "vaultClient.h"

namespace fs = std::filesystem;

extern std::unordered_set<std::string> activeSessions;
extern Config config;

ServerUtils::ServerUtils() {}

std::unique_ptr<ServerUtils> ServerUtils::instance_ = nullptr;

ServerUtils& ServerUtils::instance() {
  if (!instance_) {
    instance_ = std::unique_ptr<ServerUtils>(new ServerUtils());
  }
  return *instance_;
}

std::string ServerUtils::generateSessionToken() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);
  std::ostringstream ss;
  ss << std::hex;
  for (int i = 0; i < 32; ++i) ss << dis(gen);
  return ss.str();
}

bool ServerUtils::startsWith(const std::string& value, const std::string& start) {
  if (start.size() > value.size()) return false;
  return std::equal(start.begin(), start.end(), value.begin());
}

bool ServerUtils::endsWith(const std::string& value, const std::string& ending) {
  if (ending.size() > value.size()) return false;
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

bool ServerUtils::isAuthorized(uWS::HttpRequest* req) {
  std::string_view auth = req->getHeader("authorization");
  if (!startsWith(std::string(auth), "Bearer ")) return false;
  std::string token = std::string(auth.substr(7));
  return activeSessions.count(token) > 0;
}

bool ServerUtils::checkInternal(uWS::HttpRequest* req) {
  auto token = req->getHeader("x-internal-token");
  return token ==
         std::string(VaultClient::instance().nginxInternalToken.value().c_str());  // Hash secure
                                                                                   // string this
}

bool ServerUtils::checkOrigin(uWS::HttpRequest* req) {
  std::string_view origin = req->getHeader("origin");
  std::string expected_origin =
      "https://" + config.nginx_server_ip + ":" + std::to_string(config.nginx_server_port);
  return origin == expected_origin;
}

std::string ServerUtils::getExecutablePath() {
  fs::path path = fs::canonical("/proc/self/exe").parent_path();
  if (path.filename() == "build") {
    path = path.parent_path();
  }
  return path.string();
}

std::string ServerUtils::readPassword(const std::string& prompt = "Enter password: ") {
  std::string password;
  struct termios oldt, newt;

  std::cout << prompt;
  std::cout.flush();

  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~ECHO;

  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

  std::cout << "\n";
  return password;
}

bool ServerUtils::isAlreadyMounted(const std::string& path) {
  FILE* mtab = setmntent("/proc/mounts", "r");
  if (!mtab) return false;
  struct mntent* mnt;
  while ((mnt = getmntent(mtab)) != nullptr) {
    if (path == mnt->mnt_dir) {
      endmntent(mtab);
      return true;
    }
  }
  endmntent(mtab);
  return false;
}

std::string ServerUtils::readFile(const std::string& path) {
  std::ifstream ifs(path);
  if (!ifs) throw std::runtime_error("Failed to open: " + path);
  return std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
}