#pragma once

#include <memory>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>

using json_validator = nlohmann::json_schema::json_validator;

using json = nlohmann::json;

class Schema {
 public:
  static Schema& instance();
  void initSchemas();

 private:
  Schema();
  Schema(const Schema&) = delete;
  Schema& operator=(const Schema&) = delete;

  static std::unique_ptr<Schema> instance_;

  json getSchema(const std::string& cmd);
};
