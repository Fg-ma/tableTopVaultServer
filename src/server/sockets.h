#pragma once

#include "../../lib/uWebSockets/src/App.h"

class Sockets {
 public:
  static void initialize(uWS::SSLApp& app);
  static Sockets& instance();

 private:
  explicit Sockets(uWS::SSLApp& app);

  static std::unique_ptr<Sockets> instance_;
};
