#include "vaultClient.h"

#include <curl/curl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "share.h"

using json = nlohmann::json;

extern Config config;
extern std::optional<SecureString> password;

VaultClient::VaultClient() {}

std::unique_ptr<VaultClient> VaultClient::instance_ = nullptr;

VaultClient& VaultClient::instance() {
  if (!instance_) {
    instance_ = std::unique_ptr<VaultClient>(new VaultClient());
  }
  return *instance_;
}

size_t VaultClient::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}

std::string VaultClient::generateOneTimeToken(const std::string& request_id, int num_uses,
                                              const std::vector<std::string>& policies) {
  nlohmann::json payload = {{"policies", policies},
                            {"meta", {{"request_id", request_id}}},
                            {"ttl", "1m"},
                            {"num_uses", num_uses},
                            {"renewable", false}};
  std::string payloadStr = payload.dump();

  CURL* curl = curl_easy_init();
  std::string response;
  if (curl) {
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(
        headers, ("X-Vault-Token: " + std::string(clientToken.value().c_str())).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, config.vault_token_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, config.ca.c_str());

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  auto j = nlohmann::json::parse(response, nullptr, false);
  if (j.is_discarded() || !j.contains("auth") || !j["auth"].contains("client_token")) {
    std::cerr << "Error creating one-time token: " << response << "\n";
    return "";
  }

  return j["auth"]["client_token"].get<std::string>();
}

std::string VaultClient::fetchSecret(const std::string& path, const std::string& key) {
  CURL* curl = curl_easy_init();
  std::string response;

  if (curl) {
    std::string url = config.vault_addr + "/v1/" + path;

    struct curl_slist* headers = nullptr;
    const std::string prefix = "X-Vault-Token: ";
    std::vector<char> headerBuffer;
    headerBuffer.reserve(prefix.size() + clientToken->size() + 1);
    headerBuffer.insert(headerBuffer.end(), prefix.begin(), prefix.end());
    headerBuffer.insert(headerBuffer.end(), clientToken->c_str(),
                        clientToken->c_str() + clientToken->size());
    headerBuffer.push_back('\0');
    headers = curl_slist_append(headers, headerBuffer.data());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, config.ca.c_str());

    CURLcode res = curl_easy_perform(curl);
    sodium_memzero(headerBuffer.data(), headerBuffer.size());
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) throw std::runtime_error("Fetch secret failed");

    json j = json::parse(response);
    return j["data"]["data"][key];
  }

  throw std::runtime_error("Vault fetch: curl init failed");
}

void VaultClient::vaultLogin() {
  CURL* curl = curl_easy_init();
  std::string response;

  if (!curl) throw std::runtime_error("Vault login: curl init failed");

  std::string url = config.vault_addr + "/v1/auth/userpass/login/" + config.vault_user;

  std::string jsonStr;
  jsonStr.reserve(32 + password.value().size());
  jsonStr.append("{\"password\":\"");
  jsonStr.append(password.value().c_str(), password.value().size());
  jsonStr.append("\"}");

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  CURLcode res = curl_easy_perform(curl);

  sodium_memzero(jsonStr.data(), jsonStr.size());

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) throw std::runtime_error("Vault login failed");

  json j = json::parse(response);
  VaultClient::clientToken = SecureString(j["auth"]["client_token"]);
}

void VaultClient::fetchVaultSecrets(const std::string& tmpfsDir) {
  vaultLogin();

  std::vector<std::string> secrets = {
      "table-top-vault-server-key.pem",   "table-top-vault-server-dhparam-nginx.pem",
      "table-top-vault-server-nginx.pem", "table-top-vault-server-dhparam.pem",
      "table-top-vault-server.pem",       "table-top-vault-server-key-nginx.pem"};

  for (const auto& secret : secrets) {
    std::string vaultPath = "secret/data/vault/" + secret;
    std::string vaultContent = fetchSecret(vaultPath, "content");

    std::string filePath = tmpfsDir + "/" + secret;
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);
    if (!out) {
      std::cerr << "Failed to write: " << filePath << std::endl;
      continue;
    }
    out << vaultContent;
    out.close();

    int fd = ::open(filePath.c_str(), O_WRONLY);
    if (fd >= 0) {
      fsync(fd);
      close(fd);
    } else {
      std::cerr << "Failed to open file descriptor for fsync: " << filePath << std::endl;
    }

    chmod(filePath.c_str(), 0400);
  }

  VaultClient::nginxInternalToken =
      SecureString(fetchSecret("secret/data/vault/nginx-internal-token", "content"));

  std::string filePath = tmpfsDir + "/nginx-internal-token";
  std::ofstream out(filePath, std::ios::out | std::ios::trunc);
  if (!out) {
    std::cerr << "Failed to write: " << filePath << std::endl;
    return;
  }
  out << "default ";
  out.write(nginxInternalToken.value().c_str(), nginxInternalToken.value().size());
  out.close();

  out.flush();
  int fd = ::open(filePath.c_str(), O_RDONLY);
  if (fd >= 0) {
    fsync(fd);
    close(fd);
  }

  chmod(filePath.c_str(), 0400);
}
