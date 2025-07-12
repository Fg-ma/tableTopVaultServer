#pragma once

#include "../../lib/uWebSockets/src/App.h"

class Routes {
 public:
  static void initialize(uWS::SSLApp& app);
  static Routes& instance();

 private:
  explicit Routes(uWS::SSLApp& app);

  static std::unique_ptr<Routes> instance_;
};
