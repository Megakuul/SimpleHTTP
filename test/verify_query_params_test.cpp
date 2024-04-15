#include <iostream>
#include <string>
#include <curl/curl.h>

using namespace std;

// Callback function for curl fetch
size_t curlWriteCallback(void *contents, size_t size, size_t nmemb, string *userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}


// Defines a function to perform a test by sending a request and checking the response.
bool performTest(const string& url, long expectedCode, const string& expectedResponse) {
  CURL *curl; // Declare a variable to hold the CURL session.
  CURLcode res; // Variable to store the result of the CURL operation.
  string readBuffer; // String to store the response data.
  long response_code; // Variable to store the HTTP response code.
  bool testPassed = false; // Flag to indicate if the test passed or failed.

  // Initialize CURL session.
  curl = curl_easy_init();
  if(curl) { // Check if the CURL session was successfully initialized.
    // Set the URL for the CURL request.
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
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
    // Clean up the CURL session.
    curl_easy_cleanup(curl);
  } else {
    cerr << "Failed to initialize CURL." << endl;
  }
  return testPassed; // Return the result of the test.
}


int main(void) {
  bool allTestsPassed = true;
    
  // Test with correct query parameters
  allTestsPassed &=
    performTest(
      "http://127.0.0.1:8080/verify_query_params_test?param1=value1&param2=value2",
      200, "Parameters Validated Successfully"
    );
    
  // Test with one wrong query parameter
  allTestsPassed &=
    !performTest(
      "http://127.0.0.1:8080/verify_query_params_test?param1=wrong&param2=value2",
      400, "Incorrect or Missing Parameters"
    );
    
  // Test with missing query parameters
  allTestsPassed &=
    !performTest(
      "http://127.0.0.1:8080/verify_query_params_test",
      400, "Incorrect or Missing Parameters"
    );

  if(allTestsPassed) {
    cout << "All tests passed." << endl;
    return 0; // Indicates success
  } else {
    cout << "One or more tests failed." << endl;
    return 1; // Indicates failure
  }
}
