#include <iostream>
#include <string>
#include <curl/curl.h>

using namespace std;

// Callback function for curl fetch
size_t curlWriteCallback(void *contents, size_t size, size_t nmemb, string *userp) {
  userp->append((char*)contents, size * nmemb);
  return size * nmemb;
}

// Perform body test with chunked Transfer-Encoding
bool performTestWithBody(CURL *curl, const string& url, const string& body, int bitShift, const string& expectedResponse) {
  CURLcode res; // Variable to store the result of the CURL operation.
  string readBuffer; // String to store the response data.
  long response_code; // Variable to store the HTTP response code.
  struct curl_slist *headers = NULL; // Initialize a list for custom headers.
  bool testPassed = false; // Flag to indicate if the test passed or failed.

  // Setup custom headers for chunked transfer and bit shift.
  headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
  headers = curl_slist_append(headers, ("BitShift: " + to_string(bitShift)).c_str());

  // Reset the state of the curl session to its default state.
  curl_easy_reset(curl);
  // Set the URL for the CURL request.
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  // Set the custom headers for the CURL request.
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  // Enable the POST method for the request.
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  if (!body.empty()) {
    // Set the POST request body.
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    // For chunked transfer, the POSTFIELDSIZE is not set.
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
  for (int i = 0; i < count / pattern.size(); i++)
    result += pattern;
  // Get remainder from module and add it to the strings front
  int remainder = count % pattern.size();
  if (remainder > 0)
    result += pattern.substr(0, remainder);
  return pattern;
}

int main(void) {
  // Flag to indicate if all tests passed.
  bool allTestsPassed = true;
  // Base URL for the test server.
  string baseUrl = "http://127.0.0.1:8080";
  // The body content to send in the test request.
  string inputBody = generateStringFromPattern("SuperMegakuul!", 2500);
  // The bit shift value to be applied.
  int shift = 2;
  // Transform the body content according to the bit shift operation.
  string expectedTransformedBody = applyBitShift(inputBody, shift);

  // Initialize CURL session.
  CURL *curl = curl_easy_init();
  if (!curl) {
    // Report failure if CURL session wasn't successfully initialized.
    cerr << "Failed to initialize CURL." << endl;
    return 1; 
  }

  // Enable TCP keep-alive on the CURL handle to reuse the connection.
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

  // Test with correct body and header for chunked transfer to /process_body_readall
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readall",
    inputBody, shift, expectedTransformedBody
  );

  // Test with correct body and header for chunked transfer to /process_body_readloop
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readloop",
    inputBody, shift, expectedTransformedBody
  );

  // Test with a 0 length body for chunked transfer to /process_body_readall
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readall",
    "", shift, ""
  );

  // Test with a 0 length body for chunked transfer to /process_body_readloop
  allTestsPassed &= performTestWithBody(
    curl,
    baseUrl + "/process_body_readloop",
    "", shift, ""
  );

  // Cleanup curl session
  curl_easy_cleanup(curl);

  if(allTestsPassed) {
    cout << "All tests passed." << endl;
    return 0;
  } else {
    cout << "One or more tests failed." << endl;
    return 1;
  }
}
