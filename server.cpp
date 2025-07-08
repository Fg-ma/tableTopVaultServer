#include <yaml-cpp/yaml.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;
using json = nlohmann::json;

struct Config {
  std::string server_host;
  std::string server_port;
  std::string ca_file;
  std::string request_id, request_ip, request_purpose;
  std::vector<std::string> request_policies;
  int request_num_uses;
};

Config config;

bool load_config(const std::string& path) {
  YAML::Node root = YAML::LoadFile(path);
  auto srv = root["server"];
  auto tls = root["tls"];
  auto req = root["request"];
  config.server_host = srv["ip"].as<std::string>();
  config.server_port = srv["port"].as<std::string>();
  config.ca_file = tls["ca"].as<std::string>();
  config.request_id = req["id"].as<std::string>();
  config.request_ip = req["ip"].as<std::string>();
  config.request_purpose = req["purpose"].as<std::string>();
  config.request_policies = req["policies"].as<std::vector<std::string>>();
  config.request_num_uses = req["num_uses"].as<int>();
  return true;
}

json https_post(asio::io_context& ioc, ssl::context& ctx, const std::string& host,
                const std::string& port, const std::string& target, const json& body) {
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
  if (ec == asio::error::eof) ec = {};
  if (ec) throw beast::system_error{ec};

  return json::parse(res.body());
}

// Connects to WSS server and waits for a vault_token for the given request_id
void wait_for_approval(asio::io_context& ioc, ssl::context& ctx, const std::string& host,
                       const std::string& port, const std::string& request_id) {
  tcp::resolver resolver(ioc);
  auto results = resolver.resolve(host, port);

  websocket::stream<beast::ssl_stream<tcp::socket>> ws(ioc, ctx);

  // Connect and SSL handshake
  auto ep = asio::connect(ws.next_layer().next_layer(), results);
  ws.next_layer().handshake(ssl::stream_base::client);

  // Perform WebSocket handshake
  ws.handshake(host + ":" + port, "/ws");

  // Subscribe to updates for this request_id
  json subscribe_msg = {{"cmd", "subscribe"}, {"request_id", request_id}};
  ws.write(asio::buffer(subscribe_msg.dump()));

  // Wait for approval message
  beast::flat_buffer buffer;
  while (true) {
    buffer.consume(buffer.size());
    ws.read(buffer);
    std::string msg = beast::buffers_to_string(buffer.data());

    try {
      auto j = json::parse(msg);
      if (j.contains("request_id") && j["request_id"] == request_id && j.contains("vault_token")) {
        std::cout << j["vault_token"].get<std::string>() << std::endl;
        break;
      }
    } catch (...) {
      std::cerr << "[WARN] Invalid JSON message: " << msg << "\n";
    }
  }

  beast::error_code ec;
  ws.close(websocket::close_code::normal, ec);
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
    return 1;
  }

  if (!load_config(argv[1])) return 1;

  asio::io_context ioc;
  ssl::context ssl_ctx(ssl::context::tlsv12_client);
  ssl_ctx.set_verify_mode(ssl::verify_peer);
  ssl_ctx.load_verify_file(config.ca_file);

  // Step 1: POST /request
  json req_payload = {{"cmd", "request"},
                      {"id", config.request_id},
                      {"ip", config.request_ip},
                      {"purpose", config.request_purpose},
                      {"policies", config.request_policies},
                      {"num_uses", config.request_num_uses}};

  auto resp =
      https_post(ioc, ssl_ctx, config.server_host, config.server_port, "/request", req_payload);

  if (!resp.contains("request_id")) {
    std::cerr << "Bad /request response: " << resp.dump() << "\n";
    return 1;
  }

  std::string rid = resp["request_id"];
  std::cerr << "[INFO] Sent request. Awaiting approval for request_id: " << rid << "\n";

  // Step 2: Listen for approval via WebSocket
  wait_for_approval(ioc, ssl_ctx, config.server_host, config.server_port, rid);

  return 0;
}
