#include "routes.h"

#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <sstream>

#include "../../lib/uWebSockets/src/App.h"
#include "serverUtils.h"
#include "share.h"
#include "vaultClient.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

extern std::unordered_map<std::string, nlohmann::json_schema::json_validator> schema_map;
extern std::unordered_map<std::string, nlohmann::json> pendingRequests;
extern std::unordered_set<std::string> activeSessions;
extern std::unordered_map<std::string, std::string> completedRequests;
extern std::unordered_map<std::string, uWS::WebSocket<true, true, WSData*>*> wsClients;
extern std::string ROOT_DIR;
extern Config config;
extern std::optional<SecureString> password;

std::unique_ptr<Routes> Routes::instance_ = nullptr;

void Routes::initialize(uWS::SSLApp& app) {
  if (!instance_) {
    instance_ = std::unique_ptr<Routes>(new Routes(app));
  }
}

Routes& Routes::instance() {
  if (!instance_) throw std::runtime_error("Routes not initialized");
  return *instance_;
}

Routes::Routes(uWS::SSLApp& app) {
  app.get("/public/*", [](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    std::string path(req->getUrl());

    std::string filePath;

    filePath = ROOT_DIR + "/src" + path;

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ServerUtils::instance().endsWith(path, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ServerUtils::instance().endsWith(path, ".js") ||
               ServerUtils::instance().endsWith(path, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ServerUtils::instance().endsWith(path, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ServerUtils::instance().endsWith(path, ".json")) {
      res->writeHeader("Content-Type", "application/json");
    } else if (ServerUtils::instance().endsWith(path, ".svg")) {
      res->writeHeader("Content-Type", "image/svg+xml");
    } else {
      res->writeHeader("Content-Type", "text/plain");
    }

    res->end(buffer.str());
  });

  app.get("/loginPage/*", [](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
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
      filePath = ROOT_DIR + path.substr(std::string("/loginPage").length());
    } else {
      filePath = ROOT_DIR + "/src" + path;
    }

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ServerUtils::instance().endsWith(path, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ServerUtils::instance().endsWith(path, ".js") ||
               ServerUtils::instance().endsWith(path, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ServerUtils::instance().endsWith(path, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ServerUtils::instance().endsWith(path, ".json")) {
      res->writeHeader("Content-Type", "application/json");
    } else {
      res->writeHeader("Content-Type", "text/plain");
    }

    res->end(buffer.str());
  });

  app.get("/dashboard/*", [](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
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
      filePath = ROOT_DIR + path.substr(std::string("/dashboard").length());
    } else {
      filePath = ROOT_DIR + "/src" + path;
    }

    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ServerUtils::instance().endsWith(path, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ServerUtils::instance().endsWith(path, ".js") ||
               ServerUtils::instance().endsWith(path, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ServerUtils::instance().endsWith(path, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ServerUtils::instance().endsWith(path, ".json")) {
      res->writeHeader("Content-Type", "application/json");
    } else {
      res->writeHeader("Content-Type", "text/plain");
    }

    res->end(buffer.str());
  });

  app.post("/login", [](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
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

        if (password.has_value() && password->constantTimeEqual(j["password"].get<std::string>())) {
          std::string sess = ServerUtils::instance().generateSessionToken();
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
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    // Handle premature disconnects
    res->onAborted([]() { std::cerr << "[/request] Aborted by client before complete body\n"; });

    // Buffer to collect POST data
    res->onData(
        [res, buf = std::make_shared<std::string>()](std::string_view data, bool last) mutable {
          buf->append(data);
          if (!last) return;

          try {
            auto j = json::parse(*buf);

            // Schema validation
            schema_map["request"].validate(j);

            // Generate a request ID and store the request
            std::string rid = "req-" + std::to_string(std::rand());
            pendingRequests[rid] = j;

            // Prepare response JSON
            json response = {{"request_id", rid}};
            std::string responseStr = response.dump();

            // Ensure full response is flushed together using cork()
            res->cork([res, responseStr = std::move(responseStr)]() {
              res->writeHeader("Content-Type", "application/json");
              res->end(responseStr);
            });

          } catch (const std::exception& e) {
            std::cerr << "[/request] JSON parse/validate error: " << e.what() << "\n";
            res->writeStatus("400 Bad Request")->end("Invalid request payload");
          }
        });
  });

  app.post("/approve", [&](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    if (!ServerUtils::instance().isAuthorized(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    res->onAborted([]() { std::cerr << "[/approve] Request aborted by client.\n"; });

    res->onData(
        [res, buf = std::make_shared<std::string>()](std::string_view data, bool last) mutable {
          buf->append(data);
          if (!last) return;

          try {
            auto j = json::parse(*buf);
            schema_map["approve"].validate(j);
            std::string rid = j["request_id"].get<std::string>();
            auto it = pendingRequests.find(rid);
            if (it == pendingRequests.end()) {
              res->writeStatus("404 Not Found")->end();
            } else {
              auto& reqData = it->second;
              auto token = VaultClient::instance().generateOneTimeToken(
                  rid, reqData["num_uses"].get<int>(),
                  reqData["policies"].get<std::vector<std::string>>());
              pendingRequests.erase(it);
              if (auto it = wsClients.find(rid); it != wsClients.end()) {
                json msg = {{"cmd", "approved"}, {"vault_token", token}};
                it->second->send(msg.dump(), uWS::OpCode::TEXT);
              }
            }
          } catch (...) {
            res->writeStatus("400 Bad Request")->end();
          }
        });
  });

  app.post("/decline", [&](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    if (!ServerUtils::instance().isAuthorized(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    res->onAborted([]() { std::cerr << "[/decline] Request aborted by client.\n"; });

    res->onData(
        [res, buf = std::make_shared<std::string>()](std::string_view data, bool last) mutable {
          buf->append(data);

          if (!last) return;

          try {
            auto j = json::parse(*buf);
            schema_map["decline"].validate(j);
            std::string rid = j["request_id"].get<std::string>();
            auto it = pendingRequests.find(rid);
            if (it == pendingRequests.end()) {
              res->writeStatus("404 Not Found")->end();
            } else {
              pendingRequests.erase(it);
              if (auto it = wsClients.find(rid); it != wsClients.end()) {
                json msg = {{"cmd", "declined"}};
                it->second->send(msg.dump(), uWS::OpCode::TEXT);
              }
            }
          } catch (...) {
            res->writeStatus("400 Bad Request")->end();
          }
        });
  });

  app.get("/list", [&](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    if (!ServerUtils::instance().isAuthorized(req)) {
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
}
