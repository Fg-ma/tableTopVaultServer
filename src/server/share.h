#pragma once

#include <chrono>
#include <string>

#include "secureString.h"

struct Config {
  std::string ca;
  std::string secrets;
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

struct SessionInfo {
  SecureString token;
  std::chrono::steady_clock::time_point expiresAt;

  SessionInfo(SecureString&& t, std::chrono::steady_clock::time_point e)
      : token(std::move(t)), expiresAt(e) {}

  SessionInfo(SessionInfo&&) noexcept = default;
  SessionInfo& operator=(SessionInfo&&) noexcept = default;

  SessionInfo(const SessionInfo&) = delete;
  SessionInfo& operator=(const SessionInfo&) = delete;
};