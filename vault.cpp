#include <curl/curl.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sodium.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "lib/uWebSockets/src/App.h"
#include "src/server/nginx.h"
#include "src/server/routes.h"
#include "src/server/schema.h"
#include "src/server/secureString.h"
#include "src/server/serverUtils.h"
#include "src/server/share.h"
#include "src/server/sockets.h"
#include "src/server/vaultClient.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

std::string securePath;
bool mountedTmpfs = false;

std::unordered_map<std::string, uWS::WebSocket<true, true, WSData*>*> wsClients;
std::unordered_set<std::string> activeSessions;
std::unordered_map<std::string, json> pendingRequests;
std::unordered_map<std::string, std::string> completedRequests;
std::optional<SecureString> password;

std::string ROOT_DIR = ServerUtils::instance().getExecutablePath();

Config config;

bool load_config(const std::string& path) {
  try {
    auto cfg = YAML::LoadFile(path);
    auto share = cfg["share"];
    config.ca = share["ca"].as<std::string>();
    auto srv = cfg["server"];
    config.server_ip = srv["ip"].as<std::string>();
    config.server_port = srv["port"].as<int>();
    auto nginx = cfg["nginx"];
    config.nginx_server_ip = nginx["ip"].as<std::string>();
    config.nginx_server_port = nginx["port"].as<int>();
    config.nginx_install = nginx["install"].as<std::string>();
    config.nginx_pid = nginx["pid"].as<std::string>();
    config.nginx_logs = nginx["logs"].as<std::string>();
    config.nginx_internal_token = nginx["internal_token"].as<std::string>();
    config.nginx_cert = nginx["cert"].as<std::string>();
    config.nginx_key = nginx["key"].as<std::string>();
    config.nginx_dhparam = nginx["dhparam"].as<std::string>();
    auto vlt = cfg["vault"];
    config.vault_ip = vlt["ip"].as<std::string>();
    config.vault_port = vlt["port"].as<int>();
    config.vault_addr = vlt["addr"].as<std::string>();
    config.vault_user = vlt["user"].as<std::string>();
    config.vault_token_url = vlt["token_url"].as<std::string>();
    config.vault_lookup_url = vlt["lookup_url"].as<std::string>();
    auto tls = cfg["tls"];
    config.vault_cert = tls["cert"].as<std::string>();
    config.vault_key = tls["key"].as<std::string>();
    config.vault_dhparam = tls["dhparam"].as<std::string>();
    return true;
  } catch (const std::exception& e) {
    std::cerr << "Config load error: " << e.what() << std::endl;
    return false;
  }
}

void secureWipeDirectory(const std::string& dirPath) {
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

void cleanup(int signum) {
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

int main(int argc, char** argv) {
  try {
    std::atexit([]() { cleanup(0); });

    struct sigaction sa{};
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    if (argc != 2) {
      std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
      return 1;
    }
    if (!load_config(argv[1]) || sodium_init() < 0) return 1;

    password =
        SecureString(std::move(ServerUtils::instance().readPassword("Enter Vault password: ")));

    char tmpfsDir[] = "/home/fg/Desktop/tableTopVaultServer/secrets";
    if (!mkdir(tmpfsDir, 0700)) {
      perror("mkdir failed");
      return 1;
    }

    if (!ServerUtils::instance().isAlreadyMounted(tmpfsDir)) {
      if (mount("tmpfs", tmpfsDir, "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                "size=1M,mode=0700") != 0) {
        perror("mount tmpfs failed");
        rmdir(tmpfsDir);
        return 1;
      }
    }

    // Set restrictive permissions just in case
    chmod(tmpfsDir, 0700);

    // Now tmpfsDir is your RAM-only private secure directory
    std::string securePath(tmpfsDir);

    securePath = tmpfsDir;
    mountedTmpfs = true;

    VaultClient::instance().fetchVaultSecrets(tmpfsDir);

    NGINX::instance().generateNginxConfig(ROOT_DIR + "/nginx/nginx.conf.template",
                                          ROOT_DIR + "/nginx/nginx.conf");

    system(
        "sudo /home/fg/Desktop/tableTopVaultServer/nginx-1.28.0/sbin/nginx -c "
        "/home/fg/Desktop/tableTopVaultServer/nginx/nginx.conf");

    Schema::instance().initSchemas();

    uWS::SocketContextOptions sslOpt;
    sslOpt.key_file_name = config.vault_key.c_str();
    sslOpt.cert_file_name = config.vault_cert.c_str();
    sslOpt.dh_params_file_name = config.vault_dhparam.c_str();

    uWS::SSLApp app({sslOpt});

    Sockets::initialize(app);

    Routes::initialize(app);

    app.listen(config.server_ip, config.server_port,
               [&](auto* token) {
                 if (token) {
                   std::cout << "Server listening on " << config.server_ip << ":"
                             << config.server_port << "\n";
                 }
               })
        .run();

    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "Unhandled exception: " << ex.what() << "\n";
    cleanup(1);
    return 1;
  }
}