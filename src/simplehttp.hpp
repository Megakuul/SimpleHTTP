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
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <exception>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <filesystem>
#include <format>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>


using namespace std;

namespace fs = filesystem;

namespace SimpleHTTP {

  /**
   * Http Request object retrieved upon successful connection
   *
   * This object contains http header information and functions to work with the http body
   */
  class Request {
  public:

    string getType() const noexcept {
      return type;
    }

    Request& setType(string newtype) {
      type = newtype;
      return *this;
    }
    
    string getPath() const noexcept {
      return path;
    }

    Request& setPath(string newpath) {
      path = newpath;
      return *this;
    }

    string getVersion() const noexcept {
      return version;
    }

    Request& setVersion(string newversion) {
      version = newversion;
      return *this;
    }

    string getHeader(string key) {
      return headers[key];
    }

    Request& setHeader(string key, string value) {
      headers[key] = value;
      return *this;
    }
    
  private:
    // HTTP Type (e.g. Get, Post, etc.)
    string type;
    // HTTP Path (e.g. /api/some)
    string path;
    // HTTP Version (e.g. HTTP/1.1)
    string version;

    // HTTP headers
    unordered_map<string, string> headers;
  };

  /**
   * Http Response object used to answer the http request
   *
   * This object contains http header information
   */
  class Response {
  public:
    string getVersion() const noexcept {
      return version;
    }
    
    uint getStatusCode() const noexcept {
      return statusCode;
    }
    
    Response& setStatusCode(uint newstatuscode) {
      statusCode = newstatuscode;
      return *this;
    }

    string getStatusReason() const noexcept {
      return statusReason;
    }

    Response& setStatusReason(string newstatusreason) {
      statusReason = newstatusreason;
      return *this;
    }

    optional<string> getContentType() {
      auto it = headers.find("Content-Type");
      if (it != headers.end()) {
        return it->second;
      } else
        return nullopt;
    }

    Response& setContentType(string newcontenttype) {
      headers["Content-Type"] = newcontenttype;
      return *this;
    }

    optional<chrono::system_clock::time_point> getDate() {
      auto it = headers.find("Date");
      if (it == headers.end()) {
        return nullopt;
      }

      // Create input stream to parse the time
      istringstream iss(it->second);
      tm date_tm = {};
      // Parse from IMF_fixdate
      iss >> get_time(&date_tm, "%a, %d %b %Y %H:%M:%S");

      if (iss.fail()) {
        // If it fails return nullopt
        return nullopt;
      } else {
        // If succeeded, convert to time_t and the time_t to a time_point
        return chrono::system_clock::from_time_t(mktime(&date_tm));
      }
    }

    Response& setDate(chrono::system_clock::time_point newdate) {
      // Convert to time_t
      time_t newdate_t = chrono::system_clock::to_time_t(newdate);
      // Convert to GMT
      tm newdate_tm = *gmtime(&newdate_t);

      ostringstream oss;
      // Parse to the IMF_fixdate format
      oss << put_time(&newdate_tm, "%a, %d %b %Y %H:%M:%S GMT");
      headers["Date"] = oss.str();
      return *this;
    }

    unordered_map<string, string>& getHeaders() {
      return headers;
    }

    optional<string> getHeader(string key) {
      auto it = headers.find(key);
      if (it != headers.end()) {
        return it->second;
      } else
        return nullopt;
    }

    Response& setHeader(string key, string newvalue) {
      headers[key] = newvalue;
      return *this;
    }

    string getBody() {
      return body;
    }

    Response& setBody(string newbody) {
      body = newbody;
      headers["Content-Length"] = to_string(body.length());
      return *this;
    }

    Response& appendBody(string appendbody) {
      body += appendbody;
      headers["Content-Length"] = to_string(body.length());
      return *this;
    }
  private:
    // HTTP Version, constant as simpleHTTP only supports HTTP/1.1
    string version = "HTTP/1.1";
    // HTTP Status code, default is 200
    uint statusCode = 200;
    // HTTP Status reason, default is OK
    string statusReason = "OK";
    // HTTP headers
    unordered_map<string, string> headers;
    // Body represented as string
    string body = "";
  };

  // Namespace declared for internal helper / supporter functions & classes
  namespace internal {

    /**
     * RAII compatible and threadsafe filedescriptor wrapper
     *
     * - This wrapper will close the filedescriptor automatically on destruction
     * - All operations performed are fully thread-safe
     */
    class FileDescriptor {
    public:
      // Default constructor puts descriptor into invalid state (-1)
      FileDescriptor() : fd(-1) {};
    
      FileDescriptor(int fd) : fd(fd) {};
      // Move constructor sets descriptor to -1 so that close() will not lead to undefined behavior
      FileDescriptor(FileDescriptor&& other) {
        // Lock other descriptor lock
        lock_guard<mutex> otherLock(other.fd_mut);
        fd = other.fd.exchange(-1);
      };
      // Copy constructor is deleted, socket cannot be copied
      FileDescriptor(const FileDescriptor&) noexcept = delete;
    
      // Move assignment sets descriptor to -1 so that close() will not lead to undefined behavior    
      FileDescriptor& operator=(FileDescriptor&& other) {
        if (this != &other) {
          // Lock both descriptor locks
          lock_guard<mutex> localLock(fd_mut);
          lock_guard<mutex> otherLock(other.fd_mut);
          // Atomically set local fd to other fd and set other fd to -1
          int newfd = other.fd.exchange(-1);
          int oldfd = fd.exchange(newfd);
          // If new fd is not the same as the old fd, close the old
          if (oldfd!=newfd) {
            close(oldfd);
          }
        }
        return *this;
      };
      // Copy assignment is deleted, socket cannot be copied
      FileDescriptor& operator=(const FileDescriptor&) noexcept = delete;
    
      ~FileDescriptor() {
        // Lock to prevent race condition on writes
        lock_guard<mutex> lock(fd_mut);
        // Close socket
        close(fd);
      };

      bool operator==(const FileDescriptor& other) {
        return this->getfd() == other.getfd();
      };

      /**
       * Returns filedescriptor
       */
      int getfd() const noexcept {
        return fd;
      }

      /**
       * Closes filedescriptor manually
       */
      void closefd() {
        // Lock to prevent race condition on writes
        lock_guard<mutex> lock(fd_mut);
        // Close socket
        close(fd);
        // Invalidate descriptor
        fd = -1;
      }
    private:
      // Filedescriptor number
      // Atomic value is used in order to omit a full mutex lock on every read operation
      atomic<int> fd;
      // Mutex lock
      // Lock is used for write operations at the filedescriptor number
      // The implementation of this lock may seem a bit overcomplex for the current use case
      // but if more writer functions are implemented in the future, it will be crucial.
      mutex fd_mut;
    };


    /**
     * Stage defines various stages for a http connection
     */
    enum Stage {
      REQ = 1, // Request is currently received
      FUNC = 2, // User defined function is currently executed
      RES = 3 // Response is currently sent
    };


    /**
     * String wrapper which provides utils for serialization / deserialization
     */
    class Buffer {
    public:
      Buffer& operator=(const string& other) {
        buffer = other;
        cursor = 0;
        return *this;
      }
      
      Buffer& operator=(const char* other) {
        buffer = other;
        cursor = 0;
        return *this;
      }
      
      Buffer& operator+=(const string& other) {
        buffer += other;
        return *this;
      }

      Buffer& operator+=(const char* other) {
        buffer += other;
        return *this;
      }

      /**
       * Get char at cursor position
       */
      char current() {
        return buffer[cursor];
      }
      
      /**
       * Increment cursor and get char at new position
       *
       * If cursor is out of bound (no more data is on the buffer) nullopt is returned
       * Cursor is not incremented if the next cursor would be out of bound
       */
      optional<char> next() {
        int nextCursor = cursor+1;
        if (nextCursor<buffer.size())
          return buffer[cursor=nextCursor];
        else
          return nullopt;
      }

      /**
       * Set cursor to 0
      */
      Buffer& resetCursor() {
        cursor = 0;
        return *this;
      }

      /**
       * Set cursor to position. If pos is out of range, false is returned
       * and the cursor is not changed
       */
      bool setCursor(int newpos) {
        if (newpos<buffer.size() && newpos>=0) {
          cursor = newpos;
          return true;
        } else
          return false;
      }

      /**
       * Increment cursor by the specified amount. If the cursor is out of range, false is returned
       * and the cursor is not changed
       */
      bool incCursor(int update) {
        int nextCursor = cursor+update;
        if (nextCursor<buffer.size() && nextCursor>=0) {
          cursor = nextCursor;
          return true;
        } else
          return false;
      }
      
      /**
       * Returns wheter the buffer from index 0 is empty
       */
      bool empty() {
        return buffer.empty();
      }
      
      /**
       * Get reference to underlying cstring from index 0
       */
      const char* cstr() {
        return buffer.c_str();
      }

      /**
       * Returns the size of the buffer from index 0
       */
      int size() {
        return buffer.size();
      }

      /**
       * Get reference to underlying cstring from the cursor
       */
      const char* cstrAfterCursor() {
        return &buffer[cursor];
      }

      /**
       * Returns the size of the buffer from the cursor
       */
      int sizeAfterCursor() {
        return buffer.size() - cursor;
      }

    private:
      string buffer;
      int cursor = 0;
    };
    
    /**
     * ConnectionState holds the state of a http connection
     */
    struct ConnectionState {
      FileDescriptor fd;
      Stage stage;
      // Request buffer
      Buffer reqBuffer;
      // Response buffer
      Buffer resBuffer;
      // Request object
      Request request;
      // Response object
      Response response;
    };
  }

  

  /**
   * HTTP Server object bound to one bsd socket
   *
   * Server can run on top of *ipv4* or *unix sockets*
   *
   * Exceptions: runtime_error, logical_error, filesystem::filesystem_error
   */
  class Server {
  private:
    // Core bsd socket
    internal::FileDescriptor coreSocket;
    // Socket addr
    struct sockaddr coreSockAddr;
    // Socket flags
    int sockFlags;
    // Size of the Send / Recv buffer in bytes
    const int sockBufferSize = 8192;
    // Size of waiting incomming connections before connections are refused
    const int sockQueueSize = 128;
    // Defines the maximum epoll events handled in one loop iteration
    const int maxEventsPerLoop = 12;
    
  public:
    Server() = delete;

    /**
     * Launch Server using unix socket
     */
    Server(string unixSockPath) {
      fs::create_directories(fs::path(unixSockPath).parent_path());
      // Clean up socket, errors are ignored, if the socket cannot be cleaned up, it will fail at bind() which is fine
      unlink(unixSockPath.c_str());

      // Initialize core socket
      coreSocket = internal::FileDescriptor(socket(AF_UNIX, SOCK_STREAM, 0));
      if (coreSocket.getfd() < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create socket", strerror(errno)
          )
        );
      }
      
      // Create sockaddr_un for convenient option setting
      struct sockaddr_un* unSockAddr = (struct sockaddr_un *)&coreSockAddr;
      // Clean unSockAddr, 'cause maybe some weird libs
      // still expect it to zero out sin_zero (which C++ does not do by def)
      memset(unSockAddr, 0, sizeof(*unSockAddr));
      // Set unSockAddr options
      unSockAddr->sun_family = AF_UNIX;
      strcpy(unSockAddr->sun_path, unixSockPath.c_str());

      // Bind unix socket
      int res = bind(coreSocket.getfd(), &coreSockAddr, sizeof(coreSockAddr));
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "bind socket", strerror(errno)
          )
        );
      }

      // Retrieve current flags
      sockFlags = fcntl(coreSocket.getfd(), F_GETFL, 0);
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "read socket flags", strerror(errno)
          )
        );
      }

      // Add nonblocking flag
      sockFlags = sockFlags | O_NONBLOCK;

      // Set flags for core socket
      res = fcntl(coreSocket.getfd(), F_SETFL, sockFlags);
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "update socket flags", strerror(errno)
          )
        );
      }
      
      // Socket is closed automatically in destructor, because Socket is RAII compatible.
    };

    /**
     * Launch Server using kernel network stack
     *
     * Multiple instances of this server can be launched in parallel to increase performance.
     * BSD sockets with same *ip* and *port* combination, will automatically loadbalance *tcp* sessions.
     */
    Server(string ipAddr, u_int16_t port) {
      // Create sockaddr_in for convenient option setting
      struct sockaddr_in *inSockAddr = (struct sockaddr_in *)&coreSockAddr;
      // Clean inSockAddr, 'cause maybe some weird libs
      // still expect it to zero out sin_zero (which C++ does not do by def)
      memset(inSockAddr, 0, sizeof(*inSockAddr));
      // Set inSockAddr options
      inSockAddr->sin_family = AF_INET;
      inSockAddr->sin_port = htons(port);
      
      // Parse IPv4 addr and insert it to inSockAddr
      int res = inet_pton(AF_INET, ipAddr.c_str(), &inSockAddr->sin_addr);
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

      // Initialize core socket
      coreSocket = internal::FileDescriptor(socket(AF_INET, SOCK_STREAM, 0));
      if (coreSocket.getfd() < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create socket", strerror(errno)
          )
        );
      }

      // SO_REUSEADDR = Enable binding TIME_WAIT network ports forcefully
      // SO_REUSEPORT = Enable to cluster (lb) multiple bsd sockets with same ip + port combination
      int opt = 1; // opt 1 indicates that the options should be enabled
      res = setsockopt(coreSocket.getfd(), SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "set socket options", strerror(errno)
          )
        );
      }
      
      // Set socket recv buffer (should match a regular HTTP package for optimal performance)
      res = setsockopt(coreSocket.getfd(), SOL_SOCKET, SO_RCVBUF, &sockBufferSize, sizeof(sockBufferSize));
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "set socket options", strerror(errno)
          )
        );
      }
      // Set socket send buffer (should match a regular HTTP package for optimal performance)
      res = setsockopt(coreSocket.getfd(), SOL_SOCKET, SO_SNDBUF, &sockBufferSize, sizeof(sockBufferSize));
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "set socket options", strerror(errno)
          )
        );
      }

      // Bind socket to specified addr
      res = bind(coreSocket.getfd(), &coreSockAddr, sizeof(coreSockAddr));
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "bind socket", strerror(errno)
          )
        );
      }

      // Retrieve current flags
      sockFlags = fcntl(coreSocket.getfd(), F_GETFL, 0);
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "read socket flags", strerror(errno)
          )
        );
      }

      // Add nonblocking flag
      sockFlags = sockFlags | O_NONBLOCK;

      // Set flags for core socket
      res = fcntl(coreSocket.getfd(), F_SETFL, sockFlags);
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "update socket flags", strerror(errno)
          )
        );
      }

      // Socket is closed automatically in destructor, because Socket is RAII compatible.
    };

    /**
     * Serve launches the HTTP server
     *
     * tcp listener is initialized and the main event loop is started
     *
     * This function will run forever and block the thread, unless:
     * - the server encounters a critical error, it will then throw a runtime_error
     * - the socket is closed (e.g. with Kill()), it will then exit without error
     */
    void Serve() {
      // Start listener on core socket
      int res = listen(coreSocket.getfd(), sockQueueSize);
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "start listener", strerror(errno)
          )
        );
      }

      // Create epoll instance
      internal::FileDescriptor epollSocket(epoll_create1(0));
      if (epollSocket.getfd() < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create epoll instance", strerror(errno)
          )
        );
      }

      // Add core socket to epoll instance
      // This is just used to inform the epoll_ctl which events we are interested in
      // sock_event is not manipulated by the epoll_ctl syscall
      struct epoll_event sockEvent;
      // On core socket we are only interested in readable state, there is no need for any writes to it
      sockEvent.events = EPOLLIN;
      sockEvent.data.fd = coreSocket.getfd();
      
      res = epoll_ctl(epollSocket.getfd(), EPOLL_CTL_ADD, coreSocket.getfd(), &sockEvent);
      if (res < 0) {
        throw runtime_error(
          format(
            "Failed to initialize HTTP server ({}):\n{}",
            "add core socket to epoll instance", strerror(errno)
          )
        );
      }

      // Defines the base connection event
      // This event is copied, edited and used as input for epoll_ctl syscall
      // to register new connection events
      // It defines the default events connections are interested in
      struct epoll_event conBaseEvent;
      conBaseEvent.events = EPOLLIN | EPOLLOUT;
      
      // Buffer with list of connection events
      // This is used by the epoll instance to insert the events on every loop
      struct epoll_event conEvents[maxEventsPerLoop];

      // Map holding connection state
      // Key is the filedescriptor number of the socket
      // Value is a ConnectionState object which contains information about the connection
      // including a FileDescriptor resource
      //
      // If the map is destructed (e.g. error is thrown),
      // all sockets are closed automatically due to the RAII compatible FileDescriptor in the ConnectionState
      unordered_map<int, internal::ConnectionState> conStateMap;
      
      // Start main loop
      while (1) {
        // Wait for any epoll event (includes core socket and connections)
        // The -1 timeout means that it waits indefinitely until a event is reported
        int n = epoll_wait(epollSocket.getfd(), conEvents, maxEventsPerLoop, -1);
        if (n < 0) {
          throw runtime_error(
            format(
              "Critical failure while running HTTP server ({}):\n{}",
              "wait for incoming events", strerror(errno)
            )
          );
        }
        // Handle events
        for (int i = 0; i < n; i++) {
          // If the event is from the core socket
          if (conEvents[i].data.fd == coreSocket.getfd()) {
            // Check if error occured, if yes fetch it and return
            // For simplicity reasons there is currently no http 500 response here
            // instead sockets are closed leading to hangup signal on the client
            if (conEvents[i].events & EPOLLERR) {
              int err = 0;
              socklen_t errlen = sizeof(err);
              // Read error from sockopt
              res = getsockopt(conEvents[i].data.fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen);
              // If getsockopt failed, return unknown error
              if (res < 0) {
                throw runtime_error(
                  format(
                    "Critical failure while running HTTP server ({}):\n{}",
                    "error on core socket", "Unknown error"
                  )
                );
              } else {
                // If getsockopt succeeded, return error
                throw runtime_error(
                  format(
                    "Critical failure while running HTTP server ({}):\n{}",
                    "error on core socket", strerror(err)
                  )
                );
              }
            }

            // Check if socket hang up (happens if e.g. fd is closed)
            // Socket hang up is expected and therefore the loop is closed without errors
            if (conEvents[i].events & EPOLLHUP) {
              return;
            }

            // Prepare accept() attributes
            struct sockaddr conSockAddr = coreSockAddr;
            socklen_t conSockLen = sizeof(conSockAddr);
            // Accept connections if any (if no waiting connection, it will result will be -1 and is skipped)
            // Socket is immediately wrapped with a FileDescriptor, by this if any further action fails
            // (like e.g. epoll_ctl), the socket will be cleaned up correctly at the end of the scope
            internal::FileDescriptor conSocket(accept(coreSocket.getfd(), &conSockAddr, &conSockLen));
            if (conSocket.getfd() > 0) {
              // Copy options from base event
              struct epoll_event conEvent = conBaseEvent;
              // Add custom fd to identify the connection
              conEvent.data.fd = conSocket.getfd();
              // Add connection to list of interest on epoll instance
              res = epoll_ctl(epollSocket.getfd(), EPOLL_CTL_ADD, conSocket.getfd(), &conEvent);
              if (res == 0) {
                // Move the socket to the conStateMap
                // Local conSocket object is explicitly marked as rvalue so that it is moved,
                // otherwise it would be cleaned up immediately
                int conSockfd = conSocket.getfd(); // Copied because conSocket is moved before map[] overloader
                conStateMap[conSockfd] = internal::ConnectionState{
                  .fd = std::move(conSocket),
                  .stage = internal::Stage::REQ
                };
              }
            }
            
            
          // If the event is from a connection
          } else {
            // Find ConnectionState object
            auto conStateIter = conStateMap.find(conEvents[i].data.fd);
            if (conStateIter == conStateMap.end()) {
              // If object is not found, try deleting it from epoll as it is
              // from simplehttp considered as "unmanaged".
              epoll_ctl(epollSocket.getfd(), EPOLL_CTL_DEL, conEvents[i].data.fd, nullptr);
              continue;
            }

            // Check if underlying connection failed or hangup
            if (conEvents[i].events & EPOLLERR || conEvents[i].events & EPOLLHUP) {
              // Erase from map, this will destruct the FileDescriptor which cleans up the socket.
              // At the moment I do not see sufficient reason to handle error further
              conStateMap.erase(conStateIter);
              continue;
            }

            // Handle current stage
            switch (conStateIter->second.stage) {
            case internal::Stage::REQ:
              // Only process if EPOLLIN event is reported
              if (conEvents[i].events & EPOLLIN) {
                // Continue processing request
                if (!ProcessRequest(conStateIter->second)) {
                  // If encountered critical error, just close connection (erase from map)
                  conStateMap.erase(conStateIter);
                }
              }
              break;
            case internal::Stage::FUNC:
              break;
            case internal::Stage::RES:
              // Only process if EPOLLOUT event is reported
              if (conEvents[i].events & EPOLLIN) {
                // Continue sending response
                if (!ProcessResponse(conStateIter->second)) {
                  // If encountered critical error or explicit close request (Connection: close)
                  // close connection (erase from map)
                  conStateMap.erase(conStateIter);
                }
              }
              break;
            }
          }
        }
      }
    };



    /**
     * Kill shuts down the server
     *
     * tcp/unix will shut down gracefully; http will be forcefully closed (no 500 status)
     *
     * Kill() will essentially close the core socket of the server
     * This leads to the following events:
     * - Immediately new tcp connections to the server are rejected
     * - Running sessions are closed on tcp level in the next event loop
     * - The blocking Serve() will exit after next event loop
     *
     * Kill is thread-safe.
     */
    void Kill() {
      coreSocket.closefd();
    }
    
  private:
    bool ProcessRequest(internal::ConnectionState &state) {
      while (1) {
        // We take the socket buffersize to read everything at once (if available)
        char buffer[sockBufferSize+1];
        int n = recv(state.fd.getfd(), buffer, sockBufferSize, 0);
        if (n < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Skip if no data is available to read
            return true;
          } else {
            // Exit and close connection on error
            return false;
          }
        }
        // Append string end
        buffer[n] = '\0';
        // Append buffer str to state buffer
        state.reqBuffer += buffer;

        // Parse current buffer
        try {
          DeserializeRequest(state.reqBuffer, state.request);
        } catch (exception &e) {
          state.response
            .setStatusCode(400)
            .setStatusReason("Bad Request")
            .setContentType("text/plain")
            .setBody(e.what());
          state.stage = internal::RES;
          return true;
        }
      }
    }

    /**
     * Deserializes buffer into request
     *
     * This function works no matter where the buffer cursor is,
     * it parses based on the content of the request members.
     * The function will parse the full buffer into the request.
     * 
     * Parsing errors will lead to an exception
     */
    void DeserializeRequest(internal::Buffer &buffer, Request &request) {
      string identifier = "";
      optional<char> c;

      // If type is empty, parse it
      if (request.getType().empty()) {
        while (1) {
          if (!(c = buffer.next()).has_value()) {
            return;
          }
          if (c.value()==' ') {
            request.setType(identifier);
            break;
          }
          identifier += c.value();
        }
      }
      // If path is empty, parse it
      if (request.getPath().empty()) {

      }
      // If version is empty, parse it
      if (request.getVersion().empty()) {

      }


      
    }

    bool ProcessResponse(internal::ConnectionState &state) {
      if (state.resBuffer.empty()) {
        // Set date header to now
        state.response.setDate(chrono::system_clock::now());
        // Serialize response
        SerializeResponse(state.response, state.resBuffer);
      }
      while(1) {
        int n = send(
          state.fd.getfd(),
          state.resBuffer.cstrAfterCursor(),
          state.resBuffer.sizeAfterCursor(), 0
        );
        if (n < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Skip if no data is available to read
            return true;
          } else {
            // Exit and close connection on error
            return false;
          }
        }
        // Increment res buffer by the read bytes
        state.resBuffer.incCursor(n);
        // Check if all data is sent, if yes the operation is finished
        if (state.resBuffer.sizeAfterCursor() < 1) {
          // If connection header is set to "close". Explicitly close the connection
          if (state.request.getHeader("Connection")=="close") {
            return false;
          }
          // Reset connection state by creating a new object and moving the fd
          state = internal::ConnectionState{
            .fd = std::move(state.fd),
            .stage = internal::Stage::REQ
          };
          return true;
        }
      }
    }

    /**
     * Serializes response into buffer
     *
     * Unlike the deserialization function, this will serialize the full response into the buffer
     * at once.
     */
    void SerializeResponse(Response &response, internal::Buffer &buffer) {
      // Initialize buffer with status line 
      buffer =
        format(
          "{} {} {}\r\n",
          response.getVersion(),
          response.getStatusCode(),
          response.getStatusReason()
        );

      // Iterate over all headers and append them
      for (auto &header : response.getHeaders()) {
        // Skip empty headers
        if (header.second.empty()) {
          continue;
        }
        // Append header to the buffer
        buffer += format(
          "{}: {}\r\n",
          header.first,
          header.second
        );
      }

      // Append body to the buffer
      buffer += format(
        "\r\n{}",
        response.getBody()
      );
    }
  };
}

#endif
