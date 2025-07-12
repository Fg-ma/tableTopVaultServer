#include "nginx.h"

#include <fstream>

#include "serverUtils.h"
#include "share.h"

extern Config config;

NGINX::NGINX() {}

std::unique_ptr<NGINX> NGINX::instance_ = nullptr;

NGINX& NGINX::instance() {
  if (!instance_) {
    instance_ = std::unique_ptr<NGINX>(new NGINX());
  }
  return *instance_;
}

void NGINX::generateNginxConfig(const std::string& templatePath, const std::string& outputPath) {
  std::unordered_map<std::string, std::string> nginxVars = {
      {"PID", config.nginx_pid},
      {"LOGS", config.nginx_logs},
      {"INSTALL", config.nginx_install},
      {"INTERNAL_TOKEN", config.nginx_internal_token},
      {"IP", config.nginx_server_ip},
      {"PORT", std::to_string(config.nginx_server_port)},
      {"CERT", config.nginx_cert},
      {"KEY", config.nginx_key},
      {"DHPARAM", config.nginx_dhparam},
      {"CA", config.ca},
      {"SERVER_PORT", std::to_string(config.server_port)},
  };

  std::string content = ServerUtils::instance().readFile(templatePath);

  for (const auto& [key, value] : nginxVars) {
    std::string placeholder = "{{ " + key + " }}";
    size_t pos;
    while ((pos = content.find(placeholder)) != std::string::npos) {
      content.replace(pos, placeholder.length(), value);
    }
  }

  std::ofstream ofs(outputPath);
  if (!ofs) throw std::runtime_error("Failed to write to: " + outputPath);
  ofs << content;
}