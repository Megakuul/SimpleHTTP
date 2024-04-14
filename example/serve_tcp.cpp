#include <vector>

#include "src/simplehttp.hpp"

using namespace SimpleHTTP;
using namespace std;

vector<string> list;

const string TOKEN = "DontHardcodeMe";

int main(void) {
  // Create a server and optional customize the configuration
  SimpleHTTP::Server server("0.0.0.0", 8080, {
    .maxHeaderSize = 4096,
    .connectionTimeout = chrono::seconds(60)
  });

  // Create route to redirect request
  // Test with: curl 127.0.0.1:8080/cloudflare -v
  server.Route("GET", "/cloudflare", [](Request &req, Body &body, Response &res) -> Task<bool> {
    // Define response object
    res
      .setStatusCode(301)
      .setStatusReason("Moved Permanently")
      .setHeader("Location", "https://1.1.1.1")
      .setContentType("text/html")
      .setBody("<h1>Page Moved 301</h1>");

    co_return true;
  });

  // Create route to add an element to the list
  // Test with: curl -X POST -H "Authorization: DontHardcodeMe" -d "Whaazzzzuppp" 127.0.0.1:8080/add -v
  server.Route("POST", "/add", [](Request &req, Body &body, Response &res) -> Task<bool> {
    // Obtain token from authorization header
    auto tokenHeader = req.getHeader("authorization");
    if (!tokenHeader.has_value() || tokenHeader.value()!=TOKEN) {
      res
        .setStatusCode(401)
        .setStatusReason("Unauthorized")
        .setContentType("text/plain")
        .setBody("Invalid authorization token provided!\n");
      
      co_return true;
    }
    
    // Read all data from the body
    vector<unsigned char> data = co_await body.readAll();
    
    // Insert data into the list
    list.push_back(string(data.begin(), data.end()));

    res
      .setStatusCode(200)
      .setStatusReason("OK");

    co_return true;
  });

  // Create route to read an element from the list
  // Test with: curl 127.0.0.1:8080/get?index=1 -v
  server.Route("GET", "/get", [](Request &req, Body &body, Response &res) -> Task<bool> {
    try {
      // Obtain index string from query parameter
      auto indexParam = req.getQueryParam("index");
      if (!indexParam.has_value())
        throw runtime_error("No element index parameter was specified!");
      
      // Convert index string to integer
      int index = stoi(req.getQueryParam("index").value());
      
      // Obtain object from vector
      string item = list.at(index);
      
      res
        .setStatusCode(200)
        .setStatusReason("OK")
        .setContentType("text/plain")
        .setBody(item+"\n");
    } catch (exception &_) {
      res
        .setStatusCode(404)
        .setStatusReason("Not Found")
        .setContentType("text/plain")
        .setBody("Element was not found!\n");
    }
    
    co_return true;
  });
  
  // Launch server
  server.Serve();
}
