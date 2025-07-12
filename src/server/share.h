#pragma once

#include <string>

struct Config {
  std::string ca;
  std::string server_ip;
  int server_port;
  std::string nginx_server_ip;
  int nginx_server_port;
  std::string nginx_install;
  std::string nginx_pid;
  std::string nginx_logs;
  std::string nginx_internal_token;
  std::string nginx_cert;
  std::string nginx_key;
  std::string nginx_dhparam;
  std::string vault_ip;
  int vault_port;
  std::string vault_addr;
  std::string vault_user;
  std::string vault_token_url;
  std::string vault_lookup_url;
  std::string vault_cert;
  std::string vault_key;
  std::string vault_dhparam;
};

struct WSData {
  std::string request_id;
};