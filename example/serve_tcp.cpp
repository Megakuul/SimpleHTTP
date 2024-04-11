#include <chrono>
#include <random>


#include "src/simplehttp.hpp"

using namespace SimpleHTTP;
using namespace std;


int main(void) {
  // Create a server and optional customize the configuration
  SimpleHTTP::Server server("0.0.0.0", 8080, {
    .maxHeaderSize = 4096,
    .connectionTimeout = chrono::seconds(60)
  });

  // Create route to generate a random number
  server.Route("GET", "/time", [](Request &req, Body &body, Response &res) -> Task<bool> {
    // Acquire current time
    long now =  chrono::system_clock::now().time_since_epoch().count();
    // Add body to response object
    res
      .setStatusCode(200)
      .setStatusReason("OK")
      .setContentType("text/plain")
      .setBody(to_string(now)+"\n");

    // Don't close connection after response
    co_return false;
  });

  // Create route to redirect request
  server.Route("GET", "/cloudflare", [](Request &req, Body &body, Response &res) -> Task<bool> {
    // Define response object
    res
      .setStatusCode(301)
      .setStatusReason("Moved Permanently")
      .setHeader("Location", "https://1.1.1.1")
      .setContentType("text/html")
      .setBody("<h1>Page Moved 301</h1>");

    // Don't close connection after response    
    co_return true;
  });
  
  // Launch server
  server.Serve();
}
