#pragma once

#include <filesystem>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>

using json = nlohmann::json;

class Sanitize {
 public:
  static Sanitize& instance();

  std::optional<std::string> sanitizePath(const std::string& baseDir,
                                          const std::string& requestedPath);

  void recursiveSanitize(json& j,
                         const std::unordered_map<std::string, std::string>& escapeRules = {});

 private:
  Sanitize();
  Sanitize(const Sanitize&) = delete;
  Sanitize& operator=(const Sanitize&) = delete;

  static std::unique_ptr<Sanitize> instance_;

  std::string escapeChars(const std::string& input, const std::string& charsToEscape);

  std::string sanitizeToAlnum(const std::string& input);
};
