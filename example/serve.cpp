#include "src/simplehttp.hpp"

using namespace std;

int main(void) {
	SimpleHTTP::Server server("0.0.0.0", 8080);
  server.Serve();
}
