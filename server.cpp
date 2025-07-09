#include <curl/curl.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sodium.h>
#include <yaml-cpp/yaml.h>

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

#include "lib/uWebSockets/src/App.h"

namespace fs = std::filesystem;
using json = nlohmann::json;
using json_validator = nlohmann::json_schema::json_validator;

struct WSData {
  std::string request_id;
};

static std::string vaultMasterToken;
static std::unordered_map<std::string, json> pendingRequests;
static std::unordered_map<std::string, std::string> completedRequests;
static std::unordered_set<std::string> activeSessions;
static std::unordered_map<std::string, uWS::WebSocket<true, true, WSData*>*> wsClients;

struct Config {
  std::string server_ip;
  int server_port;
  std::string vault_ca;
  std::string vault_cert;
  std::string vault_key;
  std::string vault_dhparam;
  std::string vault_token_url;
  std::string vault_lookup_url;
} config;

static std::unordered_map<std::string, json_validator> schema_map;

json get_schema(const std::string& cmd) {
  if (cmd == "login") {
    return R"({
        "type":"object",
        "required":["cmd","token"],
        "properties":{
            "cmd":{"type":"string","const":"login"},
            "token":{"type":"string","minLength":10}
        }
    })"_json;
  } else if (cmd == "request") {
    return R"({
        "type":"object",
        "required":["cmd","id","ip","purpose","policies","num_uses"],
        "properties":{
            "cmd":{"type":"string","const":"request"},
            "id":{"type":"string","minLength":1},
            "ip":{"type":"string","pattern":"^(\\d{1,3}\\.){3}\\d{1,3}$"},
            "purpose":{"type":"string"},
            "policies":{"type":"array","items":{"type":"string"}},
            "num_uses":{"type":"integer","minimum":1,"maximum":10}
        }
    })"_json;
  } else if (cmd == "approve" || cmd == "decline") {
    return json{
        {"type", "object"},
        {"required", {"cmd", "request_id"}},
        {"properties",
         {
             {"cmd", {{"type", "string"}, {"const", cmd}}},
             {"request_id", {{"type", "string"}, {"minLength", 1}}},
         }},
    };
  } else if (cmd == "list") {
    return R"({
        "type":"object",
        "required":["cmd"],
        "properties":{
            "cmd":{"type":"string","const":"list"}
        }
    })"_json;
  }

  return {};
}

void init_schemas() {
  for (const auto& cmd : {"login", "request", "approve", "decline", "list"}) {
    schema_map[cmd].set_root_schema(get_schema(cmd));
  }
}

bool load_config(const std::string& path) {
  try {
    auto cfg = YAML::LoadFile(path);
    auto srv = cfg["server"];
    config.server_ip = srv["ip"].as<std::string>();
    config.server_port = srv["port"].as<int>();
    auto tls = cfg["tls"];
    config.vault_ca = tls["ca"].as<std::string>();
    config.vault_cert = tls["cert"].as<std::string>();
    config.vault_key = tls["key"].as<std::string>();
    config.vault_dhparam = tls["dhparam"].as<std::string>();
    auto vlt = cfg["vault"];
    config.vault_token_url = vlt["vault_token_url"].as<std::string>();
    config.vault_lookup_url = vlt["vault_lookup_url"].as<std::string>();
    return true;
  } catch (const std::exception& e) {
    std::cerr << "Config load error: " << e.what() << std::endl;
    return false;
  }
}

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

    curl_easy_setopt(curl, CURLOPT_URL, config.vault_token_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, config.vault_ca.c_str());

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

  curl_easy_setopt(curl, CURLOPT_URL, config.vault_lookup_url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_CAINFO, config.vault_ca.c_str());

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
  vaultMasterToken = token;
  return true;
}

auto generateSessionToken = []() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);
  std::ostringstream ss;
  ss << std::hex;
  for (int i = 0; i < 32; ++i) ss << dis(gen);
  return ss.str();
};

bool ends_with(const std::string& value, const std::string& ending) {
  if (ending.size() > value.size()) return false;
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

bool starts_with(const std::string& value, const std::string& start) {
  if (start.size() > value.size()) return false;
  return std::equal(start.begin(), start.end(), value.begin());
}

auto isAuthorized = [](uWS::HttpRequest* req) {
  std::string_view auth = req->getHeader("authorization");
  if (!starts_with(std::string(auth), "Bearer ")) return false;
  std::string token = std::string(auth.substr(7));
  return activeSessions.count(token) > 0;
};

auto checkInternal = [](uWS::HttpRequest* req) {
  auto token = req->getHeader("x-internal-token");
  return token == "s3cr3t-from-nginx";
};

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
    return 1;
  }
  if (!load_config(argv[1]) || sodium_init() < 0) return 1;
  init_schemas();

  uWS::SocketContextOptions sslOpt;
  sslOpt.key_file_name = config.vault_key.c_str();
  sslOpt.cert_file_name = config.vault_cert.c_str();
  sslOpt.dh_params_file_name = config.vault_dhparam.c_str();

  uWS::SSLApp app({sslOpt});

  app.ws<WSData*>("/ws/*", {.compression = uWS::SHARED_COMPRESSOR,
                            .maxPayloadLength = 16 * 1024,
                            .idleTimeout = 60,

                            .upgrade = [](auto* res, auto* req, auto* raw_context) -> void {
                              std::string_view url = req->getUrl();
                              std::string request_id =
                                  std::string(url.substr(url.find_last_of('/') + 1));
                              WSData* data = new WSData{request_id};

                              // raw_context is us_socket_context_t*
                              auto* context = static_cast<us_socket_context_t*>(raw_context);

                              res->template upgrade<WSData*>(
                                  std::move(data), req->getHeader("sec-websocket-key"),
                                  req->getHeader("sec-websocket-protocol"),
                                  req->getHeader("sec-websocket-extensions"), context);
                            },

                            .open =
                                [](auto* ws) {
                                  WSData* data = *ws->getUserData();  // 👈 CORRECTED
                                  wsClients[data->request_id] = ws;
                                },

                            .message =
                                [](auto* ws, std::string_view message, uWS::OpCode opCode) {
                                  WSData* data = *ws->getUserData();  // 👈 CORRECTED
                                                                      // handle message
                                },

                            .close =
                                [](auto* ws, int code, std::string_view message) {
                                  WSData* data = *ws->getUserData();  // 👈 CORRECTED
                                  wsClients.erase(data->request_id);
                                  delete data;
                                }});

  app.get("/public/*", [](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    std::string path(req->getUrl());

    std::string filePath;

    filePath = "../src" + path;

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ends_with(path, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ends_with(path, ".js") || ends_with(path, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ends_with(path, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ends_with(path, ".json")) {
      res->writeHeader("Content-Type", "application/json");
    } else if (ends_with(path, ".svg")) {
      res->writeHeader("Content-Type", "image/svg+xml");
    } else {
      res->writeHeader("Content-Type", "text/plain");
    }

    res->end(buffer.str());
  });

  app.get("/loginPage/*", [](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    std::string path(req->getUrl());

    // Redirect "/loginPage" or "/loginPage/" to index
    if (path == "/loginPage" || path == "/loginPage/") {
      path = "/loginPage/public/login.html";
    }

    std::string filePath;

    // Serve transpiled JS first
    if (path.rfind("/loginPage/dist", 0) == 0) {
      filePath = ".." + path.substr(std::string("/loginPage").length());
    } else {
      filePath = "../src" + path;
    }

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

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

  app.get("/dashboard/*", [](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    std::string path(req->getUrl());

    // Redirect "/dashboard" or "/dashboard/" to index
    if (path == "/dashboard" || path == "/dashboard/") {
      path = "/dashboard/public/dashboard.html";
    }

    std::string filePath;

    if (path.rfind("/dashboard/dist", 0) == 0) {
      filePath = ".." + path.substr(std::string("/dashboard").length());
    } else {
      filePath = "../src" + path;
    }

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

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

  app.post("/login", [](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    auto buf = std::make_shared<std::string>();

    res->onAborted([buf]() { std::cout << "Request aborted by client.\n"; });

    res->onData([buf, res](std::string_view data, bool last) {
      buf->append(data);

      if (!last) return;

      try {
        auto j = json::parse(*buf);
        schema_map["login"].validate(j);

        if (validateVaultToken(j["token"].get<std::string>())) {
          std::string sess = generateSessionToken();
          activeSessions.insert(sess);
          res->writeStatus("200 OK")
              ->writeHeader("Content-Type", "application/json")
              ->end(json{{"status", "ok"}, {"session_token", sess}}.dump());
        } else {
          res->writeStatus("401 Unauthorized")->end("Invalid token");
        }
      } catch (...) {
        res->writeStatus("400 Bad Request")->end("Invalid login payload");
      }
    });
  });

  app.post("/request", [&](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    res->onAborted([res]() { std::cerr << "[/request] Aborted by client before complete body\n"; });

    res->onData([res, buf = std::make_shared<std::string>()](std::string_view data, bool last) {
      buf->append(data);
      if (!last) return;

      try {
        auto j = json::parse(*buf);
        std::cerr << "[/request] Parsed JSON: " << j << "\n";

        schema_map["request"].validate(j);
        std::string rid = "req-" + std::to_string(std::rand());
        pendingRequests[rid] = j;

        json response = {{"request_id", rid}};
        std::cerr << "[/request] Sending response: " << response.dump() << "\n";

        res->writeHeader("Content-Type", "application/json")->end(response.dump());
      } catch (const std::exception& e) {
        std::cerr << "[/request] JSON parse/validate error: " << e.what() << "\n";
        res->writeStatus("400 Bad Request")->end("Invalid request payload");
      }
    });
  });

  app.post("/approve", [&](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }
    if (!isAuthorized(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    res->onData([&](std::string_view data, bool last) {
      static std::string buf;
      buf.append(data);
      if (!last) return;
      try {
        auto j = json::parse(buf);
        schema_map["approve"].validate(j);
        std::string rid = j["request_id"].get<std::string>();
        auto it = pendingRequests.find(rid);
        if (it == pendingRequests.end()) {
          res->writeStatus("404 Not Found")->end();
        } else {
          auto& reqData = it->second;
          auto token =
              generateOneTimeVaultToken(rid, reqData["num_uses"].get<int>(),
                                        reqData["policies"].get<std::vector<std::string>>());
          if (auto it = wsClients.find(rid); it != wsClients.end()) {
            json msg = {{"cmd", "approved"}, {"vault_token", token}};
            it->second->send(msg.dump(), uWS::OpCode::TEXT);
          }
          pendingRequests.erase(it);
        }
      } catch (...) {
        res->writeStatus("400 Bad Request")->end();
      }
      buf.clear();
    });
  });

  app.post("/decline", [&](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }
    if (!isAuthorized(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }
    res->onData([&](std::string_view data, bool last) {
      static std::string buf;
      buf.append(data);
      if (!last) return;
      try {
        auto j = json::parse(buf);
        schema_map["decline"].validate(j);
        std::string rid = j["request_id"].get<std::string>();
        if (pendingRequests.erase(rid)) {
          res->writeHeader("Content-Type", "application/json")->end("{\"status\":\"declined\"}");
        } else {
          res->writeStatus("404 Not Found")->end();
        }
      } catch (...) {
        res->writeStatus("400 Bad Request")->end();
      }
      buf.clear();
    });
  });

  app.get("/list", [&](auto* res, auto* req) {
    if (!checkInternal(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }
    if (!isAuthorized(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }
    json arr = json::array();
    for (const auto& [rid, reqData] : pendingRequests) {
      json entry = reqData;
      entry["request_id"] = rid;
      arr.push_back(entry);
    }
    res->writeHeader("Content-Type", "application/json")->end(arr.dump());
  });

  app.listen(config.server_ip, config.server_port,
             [&](auto* token) {
               if (token) {
                 std::cout << "Server listening on " << config.server_ip << ":"
                           << config.server_port << "\n";
               }
             })
      .run();

  return 0;
}