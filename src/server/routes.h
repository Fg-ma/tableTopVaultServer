#pragma once

#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <sstream>

#include "../../lib/uWebSockets/src/App.h"
#include "sanitize.h"
#include "secureJson.h"
#include "serverUtils.h"
#include "share.h"
#include "vaultClient.h"

class Routes {
 public:
  static void initialize(uWS::SSLApp& app);
  static Routes& instance();

 private:
  explicit Routes(uWS::SSLApp& app);
  Routes(const Routes&) = delete;
  Routes& operator=(const Routes&) = delete;

  static std::unique_ptr<Routes> instance_;
};
