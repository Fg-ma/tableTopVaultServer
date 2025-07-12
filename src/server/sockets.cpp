#include "sockets.h"

#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <sstream>

#include "../../lib/uWebSockets/src/App.h"
#include "share.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

extern std::unordered_map<std::string, nlohmann::json_schema::json_validator> schema_map;
extern std::unordered_map<std::string, nlohmann::json> pendingRequests;
extern std::unordered_set<std::string> activeSessions;
extern std::unordered_map<std::string, std::string> completedRequests;
extern std::unordered_map<std::string, uWS::WebSocket<true, true, WSData*>*> wsClients;
extern std::string ROOT_DIR;
extern Config config;

std::unique_ptr<Sockets> Sockets::instance_ = nullptr;

void Sockets::initialize(uWS::SSLApp& app) {
  if (!instance_) {
    instance_ = std::unique_ptr<Sockets>(new Sockets(app));
  }
}

Sockets& Sockets::instance() {
  if (!instance_) throw std::runtime_error("Sockets not initialized");
  return *instance_;
}

Sockets::Sockets(uWS::SSLApp& app) {
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
}
