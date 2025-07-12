#pragma once

#include <curl/curl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "secureString.h"
#include "share.h"

class VaultClient {
 public:
  static VaultClient& instance();

  std::string generateOneTimeToken(const std::string& request_id, int num_uses,
                                   const std::vector<std::string>& policies);

  std::string fetchSecret(const std::string& path, const std::string& key);

  void vaultLogin();

  void fetchVaultSecrets(const std::string& tmpfsDir);

  std::optional<SecureString> nginxInternalToken;

 private:
  VaultClient();
  VaultClient(const VaultClient&) = delete;
  VaultClient& operator=(const VaultClient&) = delete;

  static std::unique_ptr<VaultClient> instance_;

  std::optional<SecureString> clientToken;

  static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
};
