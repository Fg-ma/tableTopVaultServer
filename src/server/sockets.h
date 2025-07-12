#pragma once

#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <sstream>

#include "../../lib/uWebSockets/src/App.h"
#include "share.h"

class Sockets {
 public:
  static void initialize(uWS::SSLApp& app);
  static Sockets& instance();

 private:
  explicit Sockets(uWS::SSLApp& app);
  Sockets(const Sockets&) = delete;
  Sockets& operator=(const Sockets&) = delete;

  static std::unique_ptr<Sockets> instance_;
};
