#include "lib/uWebSockets/src/App.h"
#include "lib/json.hpp"
#include <iostream>

int main() {
  uWS::SSLApp app({
    .key_file_name = "certs/table-top-vault-server-key.pem",
    .cert_file_name = "certs/table-top-vault-server.pem",
    .dh_params_file_name = "certs/table-top-vault-server-dhparam.pem"
  });

  app.get("/", [](auto *res, auto *req) {
    res->writeHeader("Content-Type", "text/html")->end(R"HTML(
      <!DOCTYPE html>
      <html>
      <body>
        <h1>Vault Server GUI</h1>
        <button onclick="sendAccept()">Accept Request</button>
        <script>
          function sendAccept() {
            fetch('/accept', { method: 'POST' });
          }
        </script>
      </body>
      </html>
    )HTML");
  });
    
  app.post("/accept", [](auto *res, auto *req) {
    std::cout << "Request approved manually!\n";
    res->end("OK");
  });

  app.listen(4242, [](auto *listenSocket) {
    if (listenSocket) {
      std::cout << "Listening with TLS on port 4242...\n";
    } else {
      std::cout << "TLS listen failed.\n";
    }
  }).run();

  return 0;
}

