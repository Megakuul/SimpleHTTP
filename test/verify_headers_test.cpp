#include <iostream>
#include <string>
#include <curl/curl.h>

using namespace std;

// Callback function for curl fetch
size_t curlWriteCallback(void *contents, size_t size, size_t nmemb, string *userp) {
  userp->append((char*)contents, size * nmemb);
  return size * nmemb;
}

// Defines a function to perform a test by sending a request with custom headers and checking the response.
bool performTestWithHeaders(const string& url, const string& header1Value, const string& header2Value, long expectedCode, const string& expectedResponse) {
  CURL *curl; // Declare a variable to hold the CURL session.
  CURLcode res; // Variable to store the result of the CURL operation.
  string readBuffer; // String to store the response data.
  long response_code; // Variable to store the HTTP response code.
  struct curl_slist *headers = NULL; // Initialize a list for custom headers.
  bool testPassed = false; // Flag to indicate if the test passed or failed.

  // Append custom headers with their values to the headers list.
  headers = curl_slist_append(headers, ("Header1: " + header1Value).c_str());
  headers = curl_slist_append(headers, ("Header2: " + header2Value).c_str());

  // Initialize CURL session.
  curl = curl_easy_init();
  if(curl) { // Check if the CURL session was successfully initialized.
    // Set the URL for the CURL request.
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    // Set the custom headers for the CURL request.
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // Set the function to handle writing the data received in response.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    // Set the variable where the response data will be stored.
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    // Perform the CURL request and store the result in 'res'.
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) { // Check if the request was not successful.
      // Output the CURL error.
      cerr << "CURL error: " << curl_easy_strerror(res) << endl;
      // Clean up the CURL session.
      curl_easy_cleanup(curl);
      // Free the allocated memory for custom headers.
      curl_slist_free_all(headers);
      return false; // Return false as the test failed.
    }

    // Retrieve the HTTP response code.
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    // Check if the response code and the content of the response match expectations.
    if(response_code != expectedCode || readBuffer.find(expectedResponse) == string::npos) {
      // Output the failure details.
      cerr << "Test failed for URL: " << url << endl;
      cerr << "Expected status code: " << expectedCode << " and response: " << expectedResponse << endl;
      cerr << "Received status code: " << response_code << " and response: " << readBuffer << endl;
      testPassed = false; // Set the test result to failed.
    } else {
      testPassed = true; // Set the test result to passed if conditions are met.
    }
    // Clean up the CURL session and free allocated resources.
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  } else {
    cerr << "Failed to initialize CURL." << endl;
  }
  return testPassed; // Return the result of the test.
}


int main(void) {
  bool allTestsPassed = true;
    
  // Test with correct headers
  allTestsPassed &=
    performTestWithHeaders(
      "http://127.0.0.1:8080/verify_headers_test",
      "Value1", "Value2", 200, "Headers Verified Successfully"
    );
  
  // Test with one incorrect header
  allTestsPassed &=
    !performTestWithHeaders(
      "http://127.0.0.1:8080/verify_headers_test",
      "WrongValue", "Value2", 400, "Incorrect or Missing Headers"
    );
  
  // Test with missing headers
  allTestsPassed &=
    !performTestWithHeaders(
      "http://127.0.0.1:8080/verify_headers_test",
      "", "", 400, "Incorrect or Missing Headers"
    );

  if (allTestsPassed) {
    cout << "All tests passed." << endl;
    return 0; // Indicates success
  } else {
    cout << "One or more tests failed." << endl;
    return 1; // Indicates failure
  }
}
