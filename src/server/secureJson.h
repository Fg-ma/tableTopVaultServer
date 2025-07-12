#pragma once
#include <sodium.h>

#include <nlohmann/json.hpp>
#include <string>

class SecureJson {
 private:
  unsigned char* data = nullptr;
  size_t length = 0;

 public:
  SecureJson() = default;

  explicit SecureJson(const nlohmann::json& j) {
    std::string s = j.dump();
    length = s.size();
    data = static_cast<unsigned char*>(sodium_malloc(length));
    if (!data) throw std::bad_alloc();
    memcpy(data, s.data(), length);
  }

  ~SecureJson() {
    if (data) {
      sodium_memzero(data, length);
      sodium_free(data);
    }
  }

  SecureJson(const SecureJson&) = delete;
  SecureJson& operator=(const SecureJson&) = delete;

  SecureJson(SecureJson&& other) noexcept : data(other.data), length(other.length) {
    other.data = nullptr;
    other.length = 0;
  }
  SecureJson& operator=(SecureJson&& other) noexcept {
    if (this != &other) {
      if (data) {
        sodium_memzero(data, length);
        sodium_free(data);
      }
      data = other.data;
      length = other.length;
      other.data = nullptr;
      other.length = 0;
    }
    return *this;
  }

  nlohmann::json getJson() const {
    if (!data) return nlohmann::json{};
    std::string s(reinterpret_cast<const char*>(data), length);
    return nlohmann::json::parse(s);
  }

  size_t size() const {
    return length;
  }

  bool empty() const {
    return length == 0;
  }
};
