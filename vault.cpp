#include <signal.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include "lib/uWebSockets/src/App.h"
#include "src/server/nginx.h"
#include "src/server/routes.h"
#include "src/server/sanitize.h"
#include "src/server/schema.h"
#include "src/server/secureJson.h"
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
inline std::vector<SessionInfo> sessionList;
std::unordered_map<std::string, SecureJson> pendingRequests;
std::optional<SecureString> password;

std::string ROOT_DIR = ServerUtils::instance().getExecutablePath();

Config config;

bool load_config(const std::string& path) {
  try {
    auto cfg = YAML::LoadFile(path);
    auto share = cfg["share"];
    config.ca = share["ca"].as<std::string>();
    config.secrets = share["secrets"].as<std::string>();
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

void signalHandler(int signum) {
  ServerUtils::instance().cleanup(signum);
}

int main(int argc, char** argv) {
  try {
    std::atexit([]() { ServerUtils::instance().cleanup(0); });

    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    if (argc != 2) {
      std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
      return 1;
    }
    if (!load_config(argv[1]) || sodium_init() < 0) return 1;

    for (int attempt = 1; attempt <= 3; ++attempt) {
      try {
        password =
            SecureString(std::move(ServerUtils::instance().readPassword("Enter Vault password: ")));
        VaultClient::instance().vaultLogin();

        // Login successful, break out
        break;
      } catch (const std::exception& ex) {
        std::cerr << "Vault login failed (attempt " << attempt << "/" << 3 << "): " << ex.what()
                  << "\n";

        // Clear memory of failed password
        password.reset();

        if (attempt == 3) {
          std::cerr << "Maximum login attempts exceeded. Exiting.\n";
          return EXIT_FAILURE;
        }
      }
    }

    char tmpfsDir[PATH_MAX];
    strncpy(tmpfsDir, config.secrets.c_str(), sizeof(tmpfsDir));
    tmpfsDir[sizeof(tmpfsDir) - 1] = '\0';
    if (mkdir(config.secrets.c_str(), 0700) != 0 && errno != EEXIST) {
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
    securePath = tmpfsDir;
    mountedTmpfs = true;

    VaultClient::instance().fetchVaultSecrets(tmpfsDir);

    NGINX::instance().generateNginxConfig(ROOT_DIR + "/nginx/nginx.conf.template",
                                          ROOT_DIR + "/nginx/nginx.conf");

    system(
        "/home/fg/Desktop/tableTopVaultServer/nginx-1.29.0/sbin/nginx -c "
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
    ServerUtils::instance().cleanup(1);
    return 1;
  }
}