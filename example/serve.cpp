#include "src/simplehttp.hpp"

using namespace std;

int main(void) {
	SimpleHTTP::Server server("0.0.0.0", 8080);
  server.Route("GET", "/some", [](auto req, auto res) -> SimpleHTTP::internal::Task<void> {

    co_return;
  });
  server.Serve();
}
