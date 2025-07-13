#include "routes.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

extern std::unordered_map<std::string, nlohmann::json_schema::json_validator> schema_map;
extern std::unordered_map<std::string, SecureJson> pendingRequests;
extern std::vector<SessionInfo> sessionList;
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

    std::string rawUrl(req->getUrl());
    std::string subPath = rawUrl.substr(std::string("/public/").length());
    auto safePathOpt = Sanitize::instance().sanitizePath(ROOT_DIR + "/src/public", subPath);
    if (!safePathOpt) {
      res->writeStatus("400 Bad Request")->end("Invalid or unsafe path");
      return;
    }
    std::string safePath = *safePathOpt;

    std::ifstream file(safePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ServerUtils::instance().endsWith(safePath, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ServerUtils::instance().endsWith(safePath, ".js") ||
               ServerUtils::instance().endsWith(safePath, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ServerUtils::instance().endsWith(safePath, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ServerUtils::instance().endsWith(safePath, ".json")) {
      res->writeHeader("Content-Type", "application/json");
    } else if (ServerUtils::instance().endsWith(safePath, ".svg")) {
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

    std::string rawUrl(req->getUrl());

    // Redirect "/loginPage" or "/loginPage/" to index
    if (rawUrl == "/loginPage" || rawUrl == "/loginPage/") {
      rawUrl = "/loginPage/public/login.html";
    }

    std::string subPath = rawUrl.substr(std::string("/loginPage/").length());
    auto safePathOpt = Sanitize::instance().sanitizePath(ROOT_DIR + "/src/loginPage", subPath);
    if (!safePathOpt) {
      res->writeStatus("400 Bad Request")->end("Invalid or unsafe path");
      return;
    }
    std::string safePath = *safePathOpt;

    std::ifstream file(safePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ServerUtils::instance().endsWith(safePath, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ServerUtils::instance().endsWith(safePath, ".js") ||
               ServerUtils::instance().endsWith(safePath, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ServerUtils::instance().endsWith(safePath, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ServerUtils::instance().endsWith(safePath, ".json")) {
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

    std::string rawUrl(req->getUrl());

    // Redirect "/dashboard" or "/dashboard/" to index
    if (rawUrl == "/dashboard" || rawUrl == "/dashboard/") {
      rawUrl = "/dashboard/public/dashboard.html";
    }

    std::string subPath = rawUrl.substr(std::string("/dashboard/").length());
    auto safePathOpt = Sanitize::instance().sanitizePath(ROOT_DIR + "/src/dashboard", subPath);
    if (!safePathOpt) {
      res->writeStatus("400 Bad Request")->end("Invalid or unsafe path");
      return;
    }
    std::string safePath = *safePathOpt;

    std::ifstream file(safePath, std::ios::binary);

    if (!file) {
      res->writeStatus("404 Not Found")->end("File not found");
      return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (ServerUtils::instance().endsWith(safePath, ".css")) {
      res->writeHeader("Content-Type", "text/css");
    } else if (ServerUtils::instance().endsWith(safePath, ".js") ||
               ServerUtils::instance().endsWith(safePath, ".ts")) {
      res->writeHeader("Content-Type", "application/javascript");
    } else if (ServerUtils::instance().endsWith(safePath, ".html")) {
      res->writeHeader("Content-Type", "text/html");
    } else if (ServerUtils::instance().endsWith(safePath, ".json")) {
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
          SessionInfo sess = ServerUtils::instance().generateSessionToken();

          res->writeStatus("200 OK");
          res->writeHeader("Content-Type", "application/json");

          std::string cookieValue(sess.token.c_str(), sess.token.size());
          res->writeHeader("Set-Cookie",
                           "session_token=" + cookieValue +
                               "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600");
          std::fill(cookieValue.begin(), cookieValue.end(), '\0');

          sessionList.push_back(std::move(sess));

          res->end(json{{"status", "ok"}}.dump());
        } else {
          res->writeStatus("401 Unauthorized")->end("Invalid password");
        }
      } catch (...) {
        res->writeStatus("400 Bad Request")->end("Invalid login payload");
      }
    });
  });

  app.post("/logout", [&](auto* res, auto* req) {
    if (!ServerUtils::instance().checkInternal(req)) {
      res->writeStatus("403 Forbidden")->end();
      return;
    }

    if (!ServerUtils::instance().checkOrigin(req)) {
      res->writeStatus("401 Unauthorized")->end();
      return;
    }

    std::string_view cookieHeader = req->getHeader("cookie");
    if (cookieHeader.empty()) {
      res->writeStatus("400 Bad Request")->end("No session token");
      return;
    }

    std::string cookies{cookieHeader};
    const std::string prefix = "session_token=";
    std::string token;

    size_t pos = 0;
    while (pos < cookies.size()) {
      size_t delimPos = cookies.find(';', pos);
      std::string cookie =
          cookies.substr(pos, delimPos == std::string::npos ? std::string::npos : delimPos - pos);

      // Trim whitespace
      cookie.erase(0, cookie.find_first_not_of(" \t"));
      cookie.erase(cookie.find_last_not_of(" \t") + 1);

      if (cookie.compare(0, prefix.size(), prefix) == 0) {
        token = cookie.substr(prefix.size());
        break;
      }

      if (delimPos == std::string::npos) break;
      pos = delimPos + 1;
    }

    if (token.empty()) {
      res->writeStatus("400 Bad Request")->end("Session token not found");
      return;
    }

    // Remove the session
    sessionList.erase(
        std::remove_if(sessionList.begin(), sessionList.end(),
                       [&token](const SessionInfo& s) { return s.token.constantTimeEqual(token); }),
        sessionList.end());

    // Invalidate the cookie
    res->writeHeader("Set-Cookie",
                     "session_token=deleted; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
    res->writeStatus("200 OK")->end(json{{"status", "logged_out"}}.dump());
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

            Sanitize::instance().recursiveSanitize(
                j, {{"ip", "."}, {"policies", "-_"}, {"purpose", " "}});

            // Generate a request ID and store the request
            std::string rid = ServerUtils::instance().randomDigits(10);
            pendingRequests[rid] = SecureJson(j);

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

            Sanitize::instance().recursiveSanitize(j);

            std::string rid = j["request_id"].get<std::string>();
            auto it = pendingRequests.find(rid);

            if (it == pendingRequests.end()) {
              res->writeStatus("404 Not Found")->end();
            } else {
              json reqData = it->second.getJson();

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

            Sanitize::instance().recursiveSanitize(j);

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
    for (const auto& [rid, secureReq] : pendingRequests) {
      json entry = secureReq.getJson();
      entry["request_id"] = rid;
      arr.push_back(entry);
    }
    res->writeHeader("Content-Type", "application/json")->end(arr.dump());
  });
}
