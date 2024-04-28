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

// Defines a function to perform a test by sending a request with custom headers and checking the response.
bool performTestWithHeaders(CURL *curl, const string& url, const string& header1Value, const string& header2Value, long expectedCode, const string& expectedResponse) {
  CURLcode res; // Variable to store the result of the CURL operation.
  string readBuffer; // String to store the response data.
  long response_code; // Variable to store the HTTP response code.
  struct curl_slist *headers = NULL; // Initialize a list for custom headers.
  bool testPassed = false; // Flag to indicate if the test passed or failed.

  // Append custom headers with their values to the headers list.
  headers = curl_slist_append(headers, ("Header1: " + header1Value).c_str());
  headers = curl_slist_append(headers, ("Header2: " + header2Value).c_str());

  // Set the URL for the CURL request.
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  // Set the custom headers for the CURL request.
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  // Set the function to handle writing the data received in response.
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
  // Set the variable where the response data will be stored.
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
  // Enable TCP keep-alive on the CURL handle to reuse the connection.
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

  // Perform the CURL request and store the result in 'res'.
  res = curl_easy_perform(curl);
  if(res == CURLE_OK) {
    // Retrieve the HTTP response code.
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    // Check if the response code and the content of the response match expectations.
    if(response_code != expectedCode || readBuffer.find(expectedResponse) == string::npos) {
      // Output the failure details.
      cerr << "Test failed for URL: " << url << endl;
      cerr << "Expected status code: " << expectedCode << " and response: " << expectedResponse << endl;
      cerr << "Received status code: " << response_code << " and response: " << readBuffer << endl;
    } else {
      testPassed = true; // Set the test result to passed if conditions are met.
    }
  } else {
    // Output the CURL error.
    cerr << "CURL error: " << curl_easy_strerror(res) << endl;
  }

  curl_slist_free_all(headers); // Clean up headers after each request.
  
  return testPassed;
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
  // Flag to indicate if all tests passed.
  bool allTestsPassed = true;

  // Create test server
  Server server;

  // Initialize test server
  server.Init(host, port);

  // Define routes
  
  // This route tests the server's ability to validate headers. It expects headers 'Header1' and 'Header2'
  // with specific values ('Value1' and 'Value2' respectively). If these values are provided correctly, it 
  // returns a 200 status code with a success message. Otherwise, it returns a 400 status code indicating 
  // incorrect or missing headers.
  server.Route("GET", "/verify_headers_test", [](Request &req, Body &_, Response &res) -> Task<bool> {
    auto header1 = req.getHeader("header1");
    auto header2 = req.getHeader("header2");
    
    if (header1 && *header1 == "Value1" && header2 && *header2 == "Value2") {
      res.setStatusCode(200).setBody("Headers Verified Successfully");
    } else {
      res.setStatusCode(400).setBody("Incorrect or Missing Headers");
    }
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
    
  // Test with correct headers
  allTestsPassed &=
    performTestWithHeaders(
      curl,
      baseUrl + "/verify_headers_test",
      "Value1", "Value2", 200, "Headers Verified Successfully"
    );
  
  // Test with one incorrect header
  allTestsPassed &=
    performTestWithHeaders(
      curl,
      baseUrl + "/verify_headers_test",
      "WrongValue", "Value2", 400, "Incorrect or Missing Headers"
    );
  
  // Test with missing headers
  allTestsPassed &=
    performTestWithHeaders(
      curl,
      baseUrl + "/verify_headers_test",
      "", "", 400, "Incorrect or Missing Headers"
    );

  // Cleanup curl session
  curl_easy_cleanup(curl);

  // Kill test server
  server.Shutdown();

  // Wait for the server to exit
  serverFut.get();
  
  if (allTestsPassed) {
    cout << "All tests passed." << endl;
    return 0; // Indicates success
  } else {
    cout << "One or more tests failed." << endl;
    return 1; // Indicates failure
  }
}
