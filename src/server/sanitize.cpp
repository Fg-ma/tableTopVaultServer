#include "sanitize.h"

using json = nlohmann::json;

Sanitize::Sanitize() {}

std::unique_ptr<Sanitize> Sanitize::instance_ = nullptr;

Sanitize& Sanitize::instance() {
  if (!instance_) {
    instance_ = std::unique_ptr<Sanitize>(new Sanitize());
  }
  return *instance_;
}

std::optional<std::string> Sanitize::sanitizePath(const std::string& baseDir,
                                                  const std::string& requestedPath) {
  try {
    std::filesystem::path base = std::filesystem::canonical(baseDir);
    std::filesystem::path requested = std::filesystem::weakly_canonical(base / requestedPath);

    // Ensure the requested path is within the base
    if (std::mismatch(base.begin(), base.end(), requested.begin()).first == base.end()) {
      return requested.string();
    } else {
      return std::nullopt;
    }
  } catch (...) {
    return std::nullopt;
  }
}

std::string Sanitize::sanitizeToAlnum(const std::string& input) {
  std::string result;
  for (char c : input) {
    if (std::isalnum(static_cast<unsigned char>(c))) {
      result += c;
    }
  }
  return result;
}

std::string Sanitize::escapeChars(const std::string& input, const std::string& charsToEscape) {
  std::string result;
  for (char c : input) {
    if (charsToEscape.find(c) != std::string::npos) {
      result += '\\';
    }
    result += c;
  }
  return result;
}

void Sanitize::recursiveSanitize(json& j,
                                 const std::unordered_map<std::string, std::string>& escapeRules) {
  if (j.is_object()) {
    for (auto& [key, value] : j.items()) {
      if (value.is_string()) {
        std::string strVal = value.get<std::string>();
        auto it = escapeRules.find(key);
        if (it != escapeRules.end()) {
          value = escapeChars(strVal, it->second);
        } else {
          value = sanitizeToAlnum(strVal);
        }
      } else {
        recursiveSanitize(value, escapeRules);
      }
    }
  } else if (j.is_array()) {
    for (auto& item : j) {
      recursiveSanitize(item, escapeRules);
    }
  } else if (j.is_string()) {
    j = sanitizeToAlnum(j.get<std::string>());
  }
}
