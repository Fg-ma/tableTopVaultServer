#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "secureString.h"

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

  static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);

  std::optional<SecureString> clientToken;

  static std::unique_ptr<VaultClient> instance_;
};
