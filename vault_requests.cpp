#include <yaml-cpp/yaml.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using json = nlohmann::json;

// Config structure
struct Config {
  std::string server_host;
  std::string server_port;
  std::string ca_file;
  std::string request_id;
  std::string request_ip;
  std::string request_purpose;
  std::vector<std::string> request_policies;
  int request_num_uses;
};

Config config;

// Load YAML configuration
bool load_config(const std::string& path) {
  try {
    YAML::Node root = YAML::LoadFile(path);
    config.server_host = root["server"]["ip"].as<std::string>();
    config.server_port = root["server"]["port"].as<std::string>();
    config.ca_file = root["tls"]["ca"].as<std::string>();
    config.request_id = root["request"]["id"].as<std::string>();
    config.request_ip = root["request"]["ip"].as<std::string>();
    config.request_purpose = root["request"]["purpose"].as<std::string>();
    config.request_policies = root["request"]["policies"].as<std::vector<std::string>>();
    config.request_num_uses = root["request"]["num_uses"].as<int>();
    return true;
  } catch (const std::exception& e) {
    std::cerr << "Error loading config: " << e.what() << "\n";
    return false;
  }
}

// Make an HTTPS POST request and return JSON response
json https_post(asio::io_context& ioc, ssl::context& ctx, const std::string& host,
                const std::string& port, const std::string& target, const json& body) {
  try {
    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, port);

    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

    if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
      throw beast::system_error(
          beast::error_code(static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()));

    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(ssl::stream_base::client);

    http::request<http::string_body> req{http::verb::post, target, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, "application/json");
    req.body() = body.dump();
    req.prepare_payload();

    http::write(stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.shutdown(ec);
    if (ec == asio::error::eof) ec = {};  // ignore EOF
    if (ec) throw beast::system_error{ec};

    return json::parse(res.body());
  } catch (const std::exception& e) {
    std::cerr << "HTTPS POST error: " << e.what() << "\n";
    return {};
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
    return 1;
  }

  if (!load_config(argv[1])) return 1;

  asio::io_context ioc;
  ssl::context ssl_ctx{ssl::context::tlsv12_client};

  try {
    ssl_ctx.load_verify_file(config.ca_file);
    ssl_ctx.set_verify_mode(ssl::verify_peer);
  } catch (const std::exception& e) {
    std::cerr << "SSL context error: " << e.what() << "\n";
    return 1;
  }

  // Step 1: Send the initial request
  json request_payload = {{"cmd", "request"},
                          {"id", config.request_id},
                          {"ip", config.request_ip},
                          {"purpose", config.request_purpose},
                          {"policies", config.request_policies},
                          {"num_uses", config.request_num_uses}};

  auto resp =
      https_post(ioc, ssl_ctx, config.server_host, config.server_port, "/request", request_payload);

  if (!resp.contains("request_id")) {
    std::cerr << "Invalid /request response: " << resp.dump() << "\n";
    return 1;
  }

  std::string rid = resp["request_id"];
  std::cerr << "[INFO] Waiting for approval of request_id: " << rid << "\n";

  // Step 2: Poll /list every 2s until vault_token is available
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(2));

    json list_payload = {{"cmd", "list"}};
    auto list_resp =
        https_post(ioc, ssl_ctx, config.server_host, config.server_port, "/list", list_payload);

    if (!list_resp.is_array()) {
      std::cerr << "Invalid /list response: " << list_resp.dump() << "\n";
      continue;
    }

    for (const auto& entry : list_resp) {
      if (entry.value("request_id", "") == rid && entry.contains("vault_token")) {
        std::cout << entry["vault_token"].get<std::string>() << "\n";
        return 0;
      }
    }

    std::cerr << ".";  // Heartbeat
  }

  return 0;
}
