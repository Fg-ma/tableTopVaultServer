#pragma once

#include "../../lib/uWebSockets/src/App.h"

class NGINX {
 public:
  static NGINX& instance();

  void generateNginxConfig(const std::string& templatePath, const std::string& outputPath);

 private:
  NGINX();

  static std::unique_ptr<NGINX> instance_;
};
