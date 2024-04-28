#include <iostream>
#include <string>
#include <thread>
#include <future>

#include "curl/curl.h"
#include "simplehttp/simplehttp.hpp"

using namespace std;

using namespace SimpleHTTP;

// Attempts to connect to the server with exponential backoff.
// Returns CURLE_OK on success, or the CURL error code on failure.
CURLcode tryConnect(CURL* curl, int maxRetries, int maxDelaySeconds) {
  int retries = 0;
  int delaySeconds = 1; // Initial delay is 1 sec
  CURLcode res; 

  // Check if curl handle is valid
  if (!curl) return CURLE_FAILED_INIT;

  // Try until max retries are reached
  while (retries < maxRetries) {
    res = curl_easy_perform(curl);
    // Check if the operation was successful
    if (res == CURLE_OK) return res;
    // If not successful, wait for the exponential backoff delay
    this_thread::sleep_for(std::chrono::seconds(delaySeconds));

    // Update retries and increment delay
    retries++;
    delaySeconds *= 2;
    // If max delay is reached, cap the delay
    if (delaySeconds > maxDelaySeconds)
      delaySeconds = maxDelaySeconds;
  }
  // If all retries are exhausted, return the last error code
  cerr << "Connection failed after " << maxRetries << " retries\n";
  return res;
}

// Callback function for curl fetch
size_t curlWriteCallback(void *contents, size_t size, size_t nmemb, string *userp) {
  userp->append((char*)contents, size * nmemb);
  return size * nmemb;
}

// Callback function for curl fetch discarding data
size_t curlDiscardCallback(void *buffer, size_t size, size_t nmemb, void *userp) {
  return size * nmemb; // Indicate success but don't write the data
}

// Perform body test with fixed body
bool performTestWithBody(CURL *curl, const string& url, const string& body, int bitShift, const string& expectedResponse) {
  CURLcode res; // Variable to store the result of the CURL operation.
  string readBuffer; // String to store the response data.
  long response_code; // Variable to store the HTTP response code.
  struct curl_slist *headers = NULL; // Initialize a list for custom headers.
  bool testPassed = false; // Flag to indicate if the test passed or failed.

  // Setup custom headers
  headers = curl_slist_append(headers, ("BitShift: " + to_string(bitShift)).c_str());

  // Reset the state of the curl session to its default state.
  curl_easy_reset(curl);
  // Set the URL for the CURL request.
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  // Set the custom headers for the CURL request.
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  // Enable TCP keep-alive on the CURL handle to reuse the connection.
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
  // Enable the POST method for the request.
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  if (!body.empty()) {
    // Set the POST request body.
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
  }
  // Set the function to handle writing the data received in response.
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback); 
  // Set the variable where the response data will be stored.
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer); 

  // Perform the CURL request and store the result in 'res'
  res = curl_easy_perform(curl);
  if(res == CURLE_OK) {
    // Retrieve the HTTP response code.
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if(response_code == 200 && readBuffer == expectedResponse) {
      testPassed = true; // Set the test result to passed if conditions are met.
    } else {
      cerr << "Test failed for URL: " << url << " with shift: " << bitShift << endl;
      cerr << "Expected response: " << expectedResponse << " but got: " << readBuffer << endl;
    }
  } else {
    cerr << "CURL error: " << curl_easy_strerror(res) << endl;
  }

  curl_slist_free_all(headers); // Clean up headers after each request.

  return testPassed;
}

// Apply bit shift (pseudo hash to verify that the body is fully processed)
string applyBitShift(const string& input, int shift) {
  string result = input; // Copy the input string to result.
  for (auto &ch : result) {
    ch ^= (1 << shift); // Apply bit shift operation to each character.
  }
  return result;
}

// Generate a string from a pattern by repeating it
string generateStringFromPattern(const string& pattern, int count) {
  string result;
  for (string::size_type i = 0; i < count / pattern.size(); i++)
    result += pattern;
  // Get remainder from module and add it to the strings front
  int remainder = count % pattern.size();
  if (remainder > 0)
    result += pattern.substr(0, remainder);
  return result;
}

int main(int argc, char* argv[]) {
  // Test server port
  int port = 8000; // Default 8000
  // Check if port argument was provided
  if (argc > 1) {
    port = stoi(argv[1]);
  }
  // Test server host
  string host = "127.0.0.1";
  // Base URL for the test server.
  string baseUrl = "http://"+host+":"+to_string(port);
  // The body content to send in the test request.
  string inputBody = generateStringFromPattern("SuperMegakuul!", 2500);
  // The bit shift value to be applied.
  int shift = 2;
  // Transform the body content according to the bit shift operation.
  string expectedTransformedBody = applyBitShift(inputBody, shift);
  // Flag to indicate if all tests passed.
  bool allTestsPassed = true;

  // Create test server
  Server server({
    // Buffer is smaller then the full data block, to have multiple event loop iterations
    .sockBufferSize = 700
  });

  // Initialize test server
  server.Init(host, port);

  // Define routes

  // This route tests the server's ability to read and process the body from a POST request.
  // It applies a bitwise operation (shifting bits) to the body content based on a "bitshift" value
  // provided in the request header. The transformed body is then returned as the response.
  // If the transformation is successful, it returns a 200 status code with the modified body.
  // It uses the body.readAll() function to block until all data is read.
  server.Route("POST", "/process_body_readall", [](Request &req, Body &body, Response &res) -> Task<bool> {
    auto bitShiftHeader = req.getHeader("bitshift");
    int bitShift = bitShiftHeader ? stoi(*bitShiftHeader) : 0; // Default to no shift if header is missing
  
    auto data = co_await body.readAll();
    string dataStr(data.begin(), data.end());
    
    res.setStatusCode(200).setBody(
      applyBitShift(dataStr, bitShift)
    );
    co_return true;
  });

  // This route tests the server's ability to incrementally read and process the body from a POST request.
  // Similar to the readall route, it performs a bitwise operation (shifting bits) on the body based on a
  // "bitshift" header value after combining the chunks to form the complete transformed body.
  // The server returns this modified body with a 200 status code upon successful processing.
  // It uses the body.read(n) function to read data from the body incrementally.
  server.Route("POST", "/process_body_readloop", [](Request &req, Body &body, Response &res) -> Task<bool> {
    auto bitShiftHeader = req.getHeader("bitshift");
    int bitShift = bitShiftHeader ? stoi(*bitShiftHeader) : 0; // Default to no shift if header is missing
  
    string dataStr;
    while (true) {
      auto data = co_await body.read(512); // Read in chunks
      if (data.empty()) break; // Exit loop if no more data
      dataStr.append(data.begin(), data.end());
    }

    res.setStatusCode(200).setBody(
      applyBitShift(dataStr, bitShift)
    );
    co_return true;
  });

  // Start server in a seperate thread
  cout << "Starting local test server on " << host << ":" << port << endl;
  future<void> serverFut = async(launch::async, [&server]() {
    server.Serve();
  });
  
  // Initialize CURL session.
  CURL *curl = curl_easy_init();
  if (!curl) {
    // Report failure if CURL session wasn't successfully initialized.
    cerr << "Failed to initialize CURL." << endl;
    return 1; 
  }

  // Use base url to try connection
  curl_easy_setopt(curl, CURLOPT_URL, baseUrl.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlDiscardCallback);

  // Try to connect to the test server (5 retries, 10s maximum delay)
  CURLcode res = tryConnect(curl, 5, 10);
  if (res != CURLE_OK) {
    cerr << "Failed connecting to test server: " << curl_easy_strerror(res) << endl;
    server.Shutdown();
    return 1;
  }

  // Test with correct body and header for fixed transfer to /process_body_readall
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readall",
    inputBody, shift, expectedTransformedBody
  );

  // Test with correct body and header for fixed transfer to /process_body_readloop
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readloop",
    inputBody, shift, expectedTransformedBody
  );

  // Test with a 0 length body for fixed transfer to /process_body_readall
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readall",
    "", shift, ""
  );

  // Test with a 0 length body for fixed transfer to /process_body_readloop
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readloop",
    "", shift, ""
  );

  // Cleanup curl session
  curl_easy_cleanup(curl);

  // Kill test server
  server.Shutdown();

  // Wait for the server to exit
  serverFut.get();

  if(allTestsPassed) {
    cout << "All tests passed." << endl;
    return 0;
  } else {
    cout << "One or more tests failed." << endl;
    return 1;
  }
}
