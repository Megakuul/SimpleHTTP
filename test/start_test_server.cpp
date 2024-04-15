#include "src/simplehttp.hpp"

using namespace SimpleHTTP;

int main(void) {
  Server server("0.0.0.0", 8080, {
    // Particularly set low, so that body process operations need to go through 2 event loop iterations
    .sockBufferSize = 2048 
  });

  // This route tests the server's ability to validate query parameters. 
  // It expects 'param1' and 'param2' with specific values ('value1' and 'value2' respectively).
  // If these values are provided correctly, it returns a 200 status code with a success message. 
  // Otherwise, it returns a 400 status code indicating incorrect or missing parameters.
  server.Route("GET", "/verify_query_params_test", [](Request &req, Body &_, Response &res) -> Task<bool> {
    auto param1 = req.getQueryParam("param1");
    auto param2 = req.getQueryParam("param2");
      
    if (param1 && *param1 == "value1" && param2 && *param2 == "value2") {
      res.setStatusCode(200).setBody("Parameters Validated Successfully");
    } else {
      res.setStatusCode(400).setBody("Incorrect or Missing Parameters");
    }
    co_return true;
  });

  // This route tests the server's ability to validate headers. It expects headers 'Header1' and 'Header2'
  // with specific values ('Value1' and 'Value2' respectively). If these values are provided correctly, it 
  // returns a 200 status code with a success message. Otherwise, it returns a 400 status code indicating 
  // incorrect or missing headers.
  server.Route("GET", "/verify_headers_test", [](Request &req, Body &_, Response &res) -> Task<bool> {
    auto header1 = req.getHeader("Header1");
    auto header2 = req.getHeader("Header2");
    
    if (header1 && *header1 == "Value1" && header2 && *header2 == "Value2") {
      res.setStatusCode(200).setBody("Headers Verified Successfully");
    } else {
      res.setStatusCode(400).setBody("Incorrect or Missing Headers");
    }
    co_return true;
  });


  // This route tests the server's ability to read and process the body from a POST request.
  // It applies a bitwise operation (shifting bits) to the body content based on a "bitshift" value
  // provided in the request header. The transformed body is then returned as the response.
  // If the transformation is successful, it returns a 200 status code with the modified body.
  // It uses the body.readAll() function to block until all data is read.
  server.Route("POST", "/process_body_readall", [](Request &req, Body &body, Response &res) -> Task<bool> {
    auto bitShiftHeader = req.getHeader("BitShift");
    int shift = bitShiftHeader ? stoi(*bitShiftHeader) : 0; // Default to no shift if header is missing
  
    auto data = co_await body.readAll();
    for (auto &byte : data) {
      byte ^= (1 << shift); // Simple bit-shift transformation
    }
  
    string transformedBody(data.begin(), data.end());
    res.setStatusCode(200).setBody(transformedBody);
    co_return true;
  });

  // This route tests the server's ability to incrementally read and process the body from a POST request.
  // Similar to the readall route, it performs a bitwise operation (shifting bits) on each chunk based on a
  // "bitshift" header value, combining the chunks to form the complete transformed body.
  // The server returns this modified body with a 200 status code upon successful processing.
  // It uses the body.read(n) function to read data from the body incrementally.
  server.Route("POST", "/process_body_readloop", [](Request &req, Body &body, Response &res) -> Task<bool> {
    auto bitShiftHeader = req.getHeader("BitShift");
    int shift = bitShiftHeader ? stoi(*bitShiftHeader) : 0; // Default to no shift if header is missing
  
    vector<unsigned char> transformedData;
    while (true) {
      auto data = co_await body.read(1024); // Read in chunks
      if (data.empty()) break; // Exit loop if no more data
    
      for (auto &byte : data) {
        byte ^= (1 << shift); // Simple bit-shift transformation
      }
      transformedData.insert(transformedData.end(), data.begin(), data.end());
    }
  
    string transformedBody(transformedData.begin(), transformedData.end());
    res.setStatusCode(200).setBody(transformedBody);
    co_return true;
  });

  
  server.Serve();

  return 0;
}
