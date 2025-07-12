#pragma once
#include <sodium.h>

#include <cstring>
#include <string>

class SecureString {
  unsigned char* data;
  size_t len;

 public:
  // Construct from a std::string
  explicit SecureString(const std::string& input) {
    len = input.size();
    data = static_cast<unsigned char*>(sodium_malloc(len + 1));
    if (!data) throw std::bad_alloc();

    memcpy(data, input.data(), len);
    data[len] = '\0';  // null-terminate for c_str()
  }

  ~SecureString() {
    sodium_memzero(data, len);  // wipe memory
    sodium_free(data);          // release secure memory
  }

  // Disable copy constructor and assignment to avoid accidental leaks
  SecureString(const SecureString&) = delete;
  SecureString& operator=(const SecureString&) = delete;

  // Allow move semantics
  SecureString(SecureString&& other) noexcept : data(other.data), len(other.len) {
    other.data = nullptr;
    other.len = 0;
  }

  SecureString& operator=(SecureString&& other) noexcept {
    if (this != &other) {
      if (data) {
        sodium_memzero(data, len);
        sodium_free(data);
      }
      data = other.data;
      len = other.len;
      other.data = nullptr;
      other.len = 0;
    }
    return *this;
  }

  bool constantTimeEqual(const std::string& input) const {
    if (input.size() != len) return false;

    // Constant-time comparison
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; ++i) {
      result |= data[i] ^ static_cast<unsigned char>(input[i]);
    }
    return result == 0;
  }

  bool constantTimeEqualHash(const std::string& clientHash) const {
    if (clientHash.size() != len) return false;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; ++i) {
      result |= data[i] ^ static_cast<unsigned char>(clientHash[i]);
    }
    return result == 0;
  }

  const char* c_str() const {
    return reinterpret_cast<const char*>(data);
  }
  size_t size() const {
    return len;
  }
};
