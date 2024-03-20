#include <curl/curl.h>

#include "src/simplehttp.hpp"


using namespace std;

int main(void) {
  // TODO: Implement basic test on Unix socket
  return 0;

  CURL *curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/tmp/simplehttp.socket");

    CURLcode res = curl_easy_perform(curl);

    if (res==CURLE_OK) {
      // Do some more and check body etc.
    }

    curl_easy_cleanup(curl);
  }
}
