#include <curl/curl.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "lib/json.hpp"
#include "lib/uWebSockets/src/App.h"

namespace fs = std::filesystem;

std::string key_file = "/home/fg/Desktop/tableTopVaultServer/certs/table-top-vault-server-key.pem";
std::string cert_file = "/home/fg/Desktop/tableTopVaultServer/certs/table-top-vault-server.pem";
std::string dh_file =
    "/home/fg/Desktop/tableTopVaultServer/certs/table-top-vault-server-dhparam.pem";

std::unordered_map<std::string, nlohmann::json> pendingRequests;
std::unordered_map<std::string, std::string> completedRequests;
std::string vaultMasterToken;

static constexpr char const* VAULT_CA_FILE = "/home/fg/Desktop/tableTopSecrets/ca.pem";

static size_t CurlWrite_CallbackFunc_StdString(void* contents, size_t size, size_t nmemb,
                                               void* userp) {
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}

std::string generateOneTimeVaultToken(const std::string& request_id, int num_uses,
                                      const std::vector<std::string>& policies) {
  nlohmann::json payload = {{"policies", policies},
                            {"meta", {{"request_id", request_id}}},
                            {"ttl", "30m"},
                            {"num_uses", num_uses},
                            {"renewable", false}};
  std::string payloadStr = payload.dump();

  CURL* curl = curl_easy_init();
  std::string response;
  if (curl) {
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("X-Vault-Token: " + vaultMasterToken).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, "https://192.168.1.48:8200/v1/auth/token/create");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, VAULT_CA_FILE);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  auto j = nlohmann::json::parse(response);

  if (!j.contains("auth") || !j["auth"].contains("client_token")) {
    std::cerr << "Error creating one-time token: " << response << "\n";
    return "";
  }

  return j["auth"]["client_token"].get<std::string>();
}

bool validateVaultToken(const std::string& token) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    std::cerr << "curl init failed\n";
    return false;
  }

  std::string response;
  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, ("X-Vault-Token: " + token).c_str());

  curl_easy_setopt(curl, CURLOPT_URL, "https://192.168.1.48:8200/v1/auth/token/lookup-self");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_CAINFO, VAULT_CA_FILE);

  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  if (res == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  } else {
    std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK || http_code != 200) {
    std::cerr << "lookup-self fail (HTTP " << http_code << "): " << response << "\n";
    return false;
  }
  return true;
}

bool ends_with(const std::string& value, const std::string& ending) {
  if (ending.size() > value.size()) return false;
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

bool starts_with(const std::string& value, const std::string& start) {
  if (start.size() > value.size()) return false;
  return std::equal(start.begin(), start.end(), value.begin());
}

uWS::SSLApp* globalApp;

int main() {
  uWS::SocketContextOptions sslOptions;
  sslOptions.key_file_name = key_file.c_str();
  sslOptions.cert_file_name = cert_file.c_str();
  sslOptions.dh_params_file_name = dh_file.c_str();

  uWS::SSLApp app = uWS::SSLApp(sslOptions);

  app.get("/*", [](auto* res, auto* req) {
    std::string path(req->getUrl());
    if (path == "/") {
      path = "/index.html";
    }

    std::string filePath;

    if (starts_with(path, "/dist/")) {
      filePath = ".." + path;
    } else {
      filePath = "../dist" + path;
    }

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      // fallback to public
      filePath = "../public" + path;
      file.open(filePath, std::ios::binary);
    }

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    // Content type
    if (ends_with(path, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ends_with(path, ".js") || ends_with(path, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ends_with(path, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ends_with(path, ".json")) {
      res->writeHeader("Content-Type", "application/json");
    } else {
      res->writeHeader("Content-Type", "text/plain");
    }

    res->end(buffer.str());
  });

  app.post("/request", [](auto* res, auto* req) {
    res->onAborted([]() { std::cout << "Client disconnected before completing request\n"; });

    std::cout << "Request " << "\n";
    // capture res explicitly and keep it alive
    res->onData([res](std::string_view data, bool last) mutable {
      static std::string buffer;
      buffer.append(data);
      if (last) {
        try {
          auto json = nlohmann::json::parse(buffer);

          std::string id = json.value("id", "unknown");
          std::string request_id = "req-" + std::to_string(std::rand());

          std::cout << "Request " << id << request_id << "\n";
          pendingRequests[request_id] = json;

          res->writeHeader("Content-Type", "application/json")
              ->end("{\"status\":\"pending\", \"request_id\":\"" + request_id + "\"}");
        } catch (...) {
          res->writeStatus("400 Bad Request")->end("Invalid JSON");
        }
        buffer.clear();
      }
    });
  });

  app.post("/accept", [](auto* res, auto* req) {
    res->onAborted([]() {});
    res->onData([res](std::string_view data, bool last) mutable {
      static std::string buffer;
      buffer.append(data);

      if (!last) return;

      try {
        auto reqJson = nlohmann::json::parse(buffer);
        std::string request_id = reqJson.value("request_id", "");

        auto it = pendingRequests.find(request_id);
        if (it == pendingRequests.end()) {
          res->writeStatus("404 Not Found")->end("Request ID not found");
        } else {
          auto requestJson = it->second;

          int num_uses = requestJson.value("num_uses", 1);
          std::vector<std::string> requestedPolicies =
              requestJson.value("policies", std::vector<std::string>{});

          // Generate a real one-time Vault token:
          std::string oneTimeToken =
              generateOneTimeVaultToken(request_id, num_uses, requestedPolicies);

          // Remove from pending
          pendingRequests.erase(it);

          // Save to completedRequests for status polling
          completedRequests[request_id] = oneTimeToken;

          // Respond back to the with the token
          nlohmann::json resp = {{"status", "approved"}, {"vault_key", oneTimeToken}};
          res->writeHeader("Content-Type", "application/json")->end(resp.dump());
        }
      } catch (...) {
        res->writeStatus("400 Bad Request")->end("Invalid JSON");
      }
      buffer.clear();
    });
  });

  app.post("/decline", [](auto* res, auto* req) {
    res->onAborted([]() { std::cout << "Client disconnected during decline\n"; });

    res->onData([res](std::string_view data, bool last) mutable {
      static std::string buffer;
      buffer.append(data);
      if (last) {
        try {
          auto json = nlohmann::json::parse(buffer);
          std::string request_id = json.value("request_id", "");
          if (pendingRequests.find(request_id) == pendingRequests.end()) {
            res->writeStatus("404 Not Found")->end("Request ID not found");
            return;
          }

          pendingRequests.erase(request_id);

          res->end("{\"status\":\"declined\"}");
        } catch (...) {
          res->writeStatus("400 Bad Request")->end("Invalid JSON");
        }
        buffer.clear();
      }
    });
  });

  app.get("/requests", [](auto* res, auto* req) {
    nlohmann::json response;
    std::cout << "Pending requests " << pendingRequests << "\n";
    for (const auto& [id, request] : pendingRequests) {
      response[id] = request;
    }

    res->writeHeader("Content-Type", "application/json")->end(response.dump());
  });

  app.get("/request-status", [](auto* res, auto* req) {
    std::string request_id = std::string(req->getQuery("id"));
    std::cout << "Status requested " << request_id << "\n";
    if (pendingRequests.count(request_id)) {
      res->writeHeader("Content-Type", "application/json")->end(R"({"status":"pending"})");
    } else if (completedRequests.count(request_id)) {
      auto vault_token = completedRequests[request_id];
      res->writeHeader("Content-Type", "application/json")
          ->end("{\"status\":\"approved\", \"vault_token\":\"" + vault_token + "\"}");
    } else {
      res->writeStatus("404 Not Found")->end("Unknown request id");
    }
  });

  app.post("/login", [](auto* res, auto* req) {
    res->onAborted([]() {});
    res->onData([res](std::string_view data, bool last) mutable {
      static std::string buf;
      buf.append(data);
      if (!last) return;
      try {
        auto j = nlohmann::json::parse(buf);
        std::string token = j.value("token", "");
        // Validate token by calling Vault API
        bool valid = validateVaultToken(token);  // see below
        if (valid) {
          vaultMasterToken = token;
          res->writeHeader("Content-Type", "application/json")->end(R"({"status":"ok"})");
        } else {
          res->writeStatus("401 Unauthorized")->end("Invalid Vault token");
        }
      } catch (...) {
        res->writeStatus("400 Bad Request")->end("Bad JSON");
      }
      buf.clear();
    });
  });

  app.listen("0.0.0.0", 4242,
             [](auto* listenSocket) {
               if (listenSocket) {
                 std::cout << "Listening with TLS on port 4242...\n";
               } else {
                 std::cout << "TLS listen failed.\n";
               }
             })
      .run();

  return 0;
}
