#pragma once
#include <sodium.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

class HashedSecureString {
  unsigned char* hash_data;
  size_t hash_len;

 public:
  explicit HashedSecureString(const std::string& input) {
    hash_len = crypto_hash_sha256_BYTES;
    hash_data = static_cast<unsigned char*>(sodium_malloc(hash_len));
    if (!hash_data) throw std::bad_alloc();

    crypto_hash_sha256(hash_data, reinterpret_cast<const unsigned char*>(input.data()),
                       input.size());
  }

  ~HashedSecureString() {
    if (hash_data) {
      sodium_memzero(hash_data, hash_len);
      sodium_free(hash_data);
    }
  }

  HashedSecureString(const HashedSecureString&) = delete;
  HashedSecureString& operator=(const HashedSecureString&) = delete;

  HashedSecureString(HashedSecureString&& other) noexcept
      : hash_data(other.hash_data), hash_len(other.hash_len) {
    other.hash_data = nullptr;
    other.hash_len = 0;
  }

  HashedSecureString& operator=(HashedSecureString&& other) noexcept {
    if (this != &other) {
      if (hash_data) {
        sodium_memzero(hash_data, hash_len);
        sodium_free(hash_data);
      }
      hash_data = other.hash_data;
      hash_len = other.hash_len;
      other.hash_data = nullptr;
      other.hash_len = 0;
    }
    return *this;
  }

  // Compare this hash with a provided hex string (e.g. client-sent SHA256 hex)
  bool constantTimeEqualHex(const std::string& inputHex) const {
    if (inputHex.size() != hash_len * 2) return false;

    unsigned char decoded[crypto_hash_sha256_BYTES];
    for (size_t i = 0; i < hash_len; ++i) {
      unsigned int byte;
      if (sscanf(inputHex.c_str() + (i * 2), "%2x", &byte) != 1) {
        return false;
      }
      decoded[i] = static_cast<unsigned char>(byte);
    }

    return sodium_memcmp(hash_data, decoded, hash_len) == 0;
  }

  size_t size() const {
    return hash_len;
  }
};
