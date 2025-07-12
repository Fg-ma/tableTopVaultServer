#pragma once

#include <fstream>

#include "../../lib/uWebSockets/src/App.h"
#include "serverUtils.h"
#include "share.h"

class NGINX {
 public:
  static NGINX& instance();

  void generateNginxConfig(const std::string& templatePath, const std::string& outputPath);

 private:
  NGINX();
  NGINX(const NGINX&) = delete;
  NGINX& operator=(const NGINX&) = delete;

  static std::unique_ptr<NGINX> instance_;
};
