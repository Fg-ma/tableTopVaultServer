#include "serverUtils.h"

namespace fs = std::filesystem;

extern std::vector<SessionInfo> sessionList;
extern Config config;
extern std::string securePath;
extern bool mountedTmpfs;

ServerUtils::ServerUtils() {}

std::unique_ptr<ServerUtils> ServerUtils::instance_ = nullptr;

ServerUtils& ServerUtils::instance() {
  if (!instance_) {
    instance_ = std::unique_ptr<ServerUtils>(new ServerUtils());
  }
  return *instance_;
}

SessionInfo ServerUtils::generateSessionToken() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);

  std::ostringstream ss;
  for (int i = 0; i < 64; ++i) ss << std::hex << dis(gen);

  return SessionInfo{SecureString(std::move(ss.str())),
                     std::chrono::steady_clock::now() + std::chrono::hours(1)};
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
  std::string_view cookieHeader = req->getHeader("cookie");
  if (cookieHeader.empty()) return false;

  std::string cookies{cookieHeader};
  size_t pos = 0;
  const std::string prefix = "session_token=";
  auto now = std::chrono::steady_clock::now();

  // Clean up expired sessions before checking
  sessionList.erase(std::remove_if(sessionList.begin(), sessionList.end(),
                                   [now](const SessionInfo& s) { return s.expiresAt <= now; }),
                    sessionList.end());

  while (pos < cookies.size()) {
    size_t delimPos = cookies.find(';', pos);
    std::string cookie =
        cookies.substr(pos, delimPos == std::string::npos ? std::string::npos : delimPos - pos);

    // Trim whitespace
    cookie.erase(0, cookie.find_first_not_of(" \t"));
    cookie.erase(cookie.find_last_not_of(" \t") + 1);

    if (cookie.compare(0, prefix.size(), prefix) == 0) {
      std::string token = cookie.substr(prefix.size());

      for (const auto& session : sessionList) {
        if (session.token.constantTimeEqual(token)) {
          return true;
        }
      }
      return false;
    }

    if (delimPos == std::string::npos) break;
    pos = delimPos + 1;
  }

  return false;
}

bool ServerUtils::checkInternal(uWS::HttpRequest* req) {
  auto token = req->getHeader("x-internal-token");
  return token == std::string(VaultClient::instance().nginxInternalToken.value().c_str());
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

std::vector<char> ServerUtils::readPassword(const std::string& prompt = "Enter password: ") {
  std::vector<char> password;
  struct termios oldt{}, newt{};

  std::cout << prompt;
  std::cout.flush();

  if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
    std::perror("tcgetattr");
    return {};
  }

  newt = oldt;
  newt.c_lflag &= ~ECHO;

  if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
    std::perror("tcsetattr");
    return {};
  }

  // Read character-by-character to avoid std::string
  char ch;
  while (std::cin.get(ch) && ch != '\n') {
    password.push_back(ch);
  }

  // Restore terminal
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << std::endl;

  return password;
}

// Secure wipe after use
void secureWipe(std::vector<char>& buffer) {
  volatile char* p = buffer.data();
  for (size_t i = 0; i < buffer.size(); ++i) {
    p[i] = 0;
  }
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

void ServerUtils::secureWipeDirectory(const std::string& dirPath) {
  DIR* dir = opendir(dirPath.c_str());
  if (!dir) {
    perror(("Failed to open directory: " + dirPath).c_str());
    return;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != nullptr) {
    // skip . and ..
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

    std::string fullPath = dirPath + "/" + entry->d_name;

    struct stat st;
    if (stat(fullPath.c_str(), &st) != 0) {
      perror(("stat failed: " + fullPath).c_str());
      continue;
    }

    if (S_ISDIR(st.st_mode)) {
      // recurse
      secureWipeDirectory(fullPath);
      if (rmdir(fullPath.c_str()) != 0) {
        perror(("rmdir failed: " + fullPath).c_str());
      }
    } else if (S_ISREG(st.st_mode)) {
      // wipe the file securely
      int fd = open(fullPath.c_str(), O_WRONLY);
      if (fd < 0) {
        perror(("Failed to open file for wiping: " + fullPath).c_str());
        continue;
      }

      off_t size = st.st_size;
      if (size > 0) {
        std::vector<unsigned char> randomData(size);
        randombytes_buf(randomData.data(), size);

        ssize_t written = 0;
        size_t toWrite = size;
        const unsigned char* bufPtr = randomData.data();
        while (toWrite > 0) {
          ssize_t res = write(fd, bufPtr + written, toWrite);
          if (res <= 0) {
            perror(("Write failed while wiping file: " + fullPath).c_str());
            break;
          }
          toWrite -= res;
          written += res;
        }

        fsync(fd);
      }
      close(fd);

      // unlink after wipe
      if (unlink(fullPath.c_str()) != 0) {
        perror(("unlink failed: " + fullPath).c_str());
      }
    }
  }

  closedir(dir);
}

void ServerUtils::cleanup(int signum) {
  std::cout << "\n[*] Cleaning up...\n";

  // Wipe secrets in tmpfs dir before unmounting
  if (mountedTmpfs && !securePath.empty()) {
    std::cout << "[*] Securely wiping tmpfs directory contents: " << securePath << "\n";
    secureWipeDirectory(securePath);

    std::cout << "[*] Unmounting tmpfs and deleting directory: " << securePath << "\n";
    if (umount(securePath.c_str()) != 0) {
      perror("umount failed");
    }

    if (rmdir(securePath.c_str()) != 0) {
      perror("rmdir failed");
    }
  }

  // Stop NGINX - prefer direct kill if you have PID, else fallback to system
  std::cout << "[*] Stopping NGINX...\n";
  if (system("sudo pkill -f nginx") != 0) {
    std::cerr << "Failed to stop nginx\n";
  }

  std::cout << "[*] Checking if ports 2222 and 2223 are still bound...\n";
  system("sudo lsof -i :2222 -i :2223 || echo \"[*] Ports are clean.\"");

  std::cout << "[✔] Cleanup complete.\n";
  std::exit(0);
}

std::string ServerUtils::randomDigits(int length) {
  std::stringstream ss;
  for (int i = 0; i < length; ++i) {
    ss << (std::rand() % 10);
  }
  return ss.str();
}