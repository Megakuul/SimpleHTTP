/**
 * SimpleHTTP
 *
 * Copyright (C) 2024  Linus Ilian Moser <linus.moser@megakuul.ch>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SIMPLEHTTP_H
#define SIMPLEHTTP_H

#include <asm-generic/socket.h>
#include <string>
#include <filesystem>
#include <format>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>


using namespace std;

namespace fs = filesystem;

namespace SimpleHTTP {

	/**
	 * RAII compatible bsd socket filedescriptor wrapper
	 *
	 * Exceptions: runtime_error
	 */
	class Socket {
	public:
		Socket(int domain, int type, int protocol) {
			// Initialize bsd socket
			sockfd = socket(domain, type, protocol);
			if (sockfd < 0) {	
				throw runtime_error(
				  format(
					  "Failed to initialize HTTP server ({}):\n{}",
						"socket registration",strerror(errno)
				  )
			  );
			}
		};
		Socket(Socket&& other) noexcept : sockfd(other.sockfd) {
			if (this != &other) {
				other.sockfd = -1;
			}
		};
		// Copy constructor is deleted, socket cannot be copied
		Socket(const Socket&) noexcept = delete;
		
		Socket& operator=(Socket&& other) noexcept {
			if (this != &other) {
				sockfd = other.sockfd;
				other.sockfd = -1;
			}
		};
		// Copy assignment is deleted, socket cannot be copied
		Socket& operator=(const Socket&) noexcept = delete;
		
		~Socket() {
			close(sockfd);
		};

		const int sock() noexcept {
			return sockfd;
		}
	private:
		int sockfd;
	};

	/**
	 * HTTP Server object bound to one bsd socket
	 *
	 * Server can run on top of *ipv4* or *unix sockets*
	 *
	 * Exceptions: runtime_error, logical_error, filesystem::filesystem_error
	 */
	class Server {
	public:
		Server() = delete;
		
		Server(string unixSockPath) : socket(AF_UNIX, SOCK_STREAM, 0) {
			fs::create_directories(fs::path(unixSockPath).parent_path());

			
		};

		/**
		 * Launch Server using kernel network stack
		 *
		 * Multiple instances of this server can be launched in parallel to increase performance.
		 * BSD sockets with same *ip* and *port* combination, will automatically loadbalance *tcp* sessions.
		 */
		Server(string ipAddr, u_int16_t port) : socket(AF_INET, SOCK_STREAM, 0) {
			// Clean inSockAddr, 'cause maybe some weird libs
			// still expect it to zero out sin_zero (which C++ does not do by def)
			memset(&inSockAddr, 0, sizeof(inSockAddr));
			// Set inSockAddr options
			inSockAddr.sin_family = AF_INET;
			inSockAddr.sin_port = htons(port);
			// Parse IPv4 addr and insert it to inSockAddr
			int res = inet_pton(AF_INET, ipAddr.c_str(), &inSockAddr);
			if (res==0) {
				throw logic_error(
				  format(
						"Failed to initialize HTTP server ({}):\n{}",
						"addr parsing", "Invalid IP-Address format"
				  )
			  );
			} else if (res==-1) {
				throw runtime_error(
				  format(
						"Failed to initialize HTTP server ({}):\n{}",
						"addr parsing", strerror(errno)
				  )
			  );
			}

			// SO_REUSEADDR = Enable binding TIME_WAIT network ports forcefully
			// SO_REUSEPORT = Enable to cluster (lb) multiple bsd sockets with same ip + port combination
			int opt = 1; // opt 1 indicates that the options should be enabled
			res = setsockopt(socket.sock(), SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
			if (res < 0) {
				throw runtime_error(
				  format(
					  "Failed to initialize HTTP server ({}):\n{}",
						"set socket options", strerror(errno)
				  )
			  );
			}
			
			// Set socket recv buffer (should match a regular HTTP package for optimal performance)
			res = setsockopt(socket.sock(), SOL_SOCKET, SO_RCVBUF, &socketBufferSize, sizeof(socketBufferSize));
			if (res < 0) {
				throw runtime_error(
				  format(
					  "Failed to initialize HTTP server ({}):\n{}",
						"set socket options", strerror(errno)
				  )
			  );
			}
			// Set socket send buffer (should match a regular HTTP package for optimal performance)
			res = setsockopt(socket.sock(), SOL_SOCKET, SO_SNDBUF, &socketBufferSize, sizeof(socketBufferSize));
			if (res < 0) {
				throw runtime_error(
				  format(
					  "Failed to initialize HTTP server ({}):\n{}",
						"set socket options", strerror(errno)
				  )
			  );
			}

			// Bind socket to specified addr
			res = bind(socket.sock(), (struct sockaddr *)&inSockAddr, sizeof(inSockAddr));
			if (res < 0) {
				throw runtime_error(
          format(
					  "Failed to initialize HTTP server ({}):\n{}",
						"bind socket", strerror(errno)
          )
			  );
			}

			// Socket is closed automatically in destructor, because Socket is RAII compatible.
		};
		
		Serve() {
			
		};

	private:
		Socket socket;
		// INET socket Addr
		struct sockaddr_in inSockAddr;
		// Unix socket Addr
		struct sockaddr_un unSockAddr;
		// Size of the Send / Recv buffer in bytes
		int socketBufferSize = 8192;
		// Size of waiting incomming connections before connections are refused
		int socketQueueSize = 128;
	};

}

#endif
