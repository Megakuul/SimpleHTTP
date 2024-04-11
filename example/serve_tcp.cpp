#include "src/simplehttp.hpp"


using namespace SimpleHTTP;
using namespace std;

const string identifier = "42069";

int main(void) {
  // Create a server and optional customize the configuration
  SimpleHTTP::Server server("0.0.0.0", 8080, {
    .maxHeaderSize = 4096,
    .connectionTimeout = chrono::seconds(60)
  });

  // Define routes with their associated route handlers
  server.Route("GET", "/identifier", [](Request &req, Body &body, Response &res) -> Task<bool> {
    // Add body to response object
    res
      .setStatusCode(200)
      .setStatusReason("OK")
      .setContentType("text/plain")
      .setBody(identifier);
    // Close tcp connection after this request
    co_return false;
  });
  
  // Launch server
  server.Serve();
}
