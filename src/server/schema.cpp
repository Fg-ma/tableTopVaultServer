#include "schema.h"

std::unordered_map<std::string, json_validator> schema_map;

Schema::Schema() {}

std::unique_ptr<Schema> Schema::instance_ = nullptr;

Schema& Schema::instance() {
  if (!instance_) {
    instance_ = std::unique_ptr<Schema>(new Schema());
  }
  return *instance_;
}

json Schema::getSchema(const std::string& cmd) {
  if (cmd == "login") {
    return R"({
        "type":"object",
        "required":["cmd","password"],
        "properties":{
            "cmd":{"type":"string","const":"login"},
            "password":{"type":"string","minLength":10}
        }
    })"_json;
  } else if (cmd == "request") {
    return R"({
        "type":"object",
        "required":["cmd","id","ip","purpose","policies","num_uses"],
        "properties":{
            "cmd":{"type":"string","const":"request"},
            "id":{"type":"string","minLength":1},
            "ip":{"type":"string","pattern":"^(\\d{1,3}\\.){3}\\d{1,3}$"},
            "purpose":{"type":"string"},
            "policies":{"type":"array","items":{"type":"string"}},
            "num_uses":{"type":"integer","minimum":1,"maximum":10}
        }
    })"_json;
  } else if (cmd == "approve" || cmd == "decline") {
    return json{
        {"type", "object"},
        {"required", {"cmd", "request_id"}},
        {"properties",
         {
             {"cmd", {{"type", "string"}, {"const", cmd}}},
             {"request_id", {{"type", "string"}, {"minLength", 1}}},
         }},
    };
  } else if (cmd == "list") {
    return R"({
        "type":"object",
        "required":["cmd"],
        "properties":{
            "cmd":{"type":"string","const":"list"}
        }
    })"_json;
  }

  return {};
}

void Schema::initSchemas() {
  for (const auto& cmd : {"login", "request", "approve", "decline", "list"}) {
    schema_map[cmd].set_root_schema(getSchema(cmd));
  }
}