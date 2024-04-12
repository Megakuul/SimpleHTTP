#include <chrono>
#include <fstream>
#include <vector>

#include "src/simplehttp.hpp"

using namespace SimpleHTTP;
using namespace std;

vector<string> list;

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

    // Close connection after response
    co_return true;
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

  // Create route to add an element to the list
  server.Route("POST", "/add", [](Request &req, Body &body, Response &res) -> Task<bool> {
    // Read all data from the body
    vector<unsigned char> data = co_await body.readAll();
    // Insert data into the list
    list.push_back(string(data.begin(), data.end()));

    // Define response object
    res
      .setStatusCode(200)
      .setStatusReason("OK");

    // Don't close connection after response    
    co_return true;
  });

  // Create route to read an element from the list
  server.Route("GET", "/get", [](Request &req, Body &body, Response &res) -> Task<bool> {

    // Fetch element
    string item = list.front();
    // Define response object
    res
      .setStatusCode(200)
      .setStatusReason("OK")
      .setContentType("text/plain")
      .setBody(item);

    // Don't close connection after response    
    co_return true;
  });
  
  // Launch server
  server.Serve();
}
