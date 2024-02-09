#include <iostream>

#include "src/simplehttp.hpp"

using namespace std;

int main(void) {
	SimpleHTTP::Server server("192.168.1.1", 83);
	cout << "Hallo" << endl;
}
