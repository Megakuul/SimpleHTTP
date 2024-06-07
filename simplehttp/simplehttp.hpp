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

// Libs available on >libstdc++20 / >libc++20
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <sstream>
#include <utility>
#include <vector>

#include <unordered_map>
#include <unordered_set>

#include <cstring>
#include <ctime>
#include <filesystem>
#include <format>

#include <coroutine>

// Libs available on POSIX systems
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

// Libs only available on Linux systems
#include <sys/epoll.h>
#include <sys/eventfd.h>


/**
 * Namespace declared for internal helper / supporter functions & classes
 */ 
namespace SimpleHTTP::internal::helper {

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
      std::lock_guard<std::mutex> otherLock(other.fd_mut);
      fd = other.fd.exchange(-1);
    };
    // Copy constructor is deleted, socket cannot be copied
    FileDescriptor(const FileDescriptor&) noexcept = delete;
    
    // Move assignment sets descriptor to -1 so that close() will not lead to undefined behavior    
    FileDescriptor& operator=(FileDescriptor&& other) {
      if (this != &other) {
        // Lock both descriptor locks
        std::lock_guard<std::mutex> localLock(fd_mut);
        std::lock_guard<std::mutex> otherLock(other.fd_mut);
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
      std::lock_guard<std::mutex> lock(fd_mut);
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
      std::lock_guard<std::mutex> lock(fd_mut);
      // Close socket
      close(fd);
      // Invalidate descriptor
      fd = -1;
    }
  private:
    // Filedescriptor number
    // Atomic value is used in order to omit a full mutex lock on every read operation
    std::atomic<int> fd;
    // Mutex lock
    // Lock is used for write operations at the filedescriptor number
    // The implementation of this lock may seem a bit overcomplex for the current use case
    // but if more writer functions are implemented in the future, it will be crucial.
    std::mutex fd_mut;
  };


  /**
   * String wrapper providing head and rollback cursor for efficient parsing
   */
  class Buffer {
  public:
    Buffer() {};
      
    /**
     * Initialize buffer, move other buffer data and reset cursor
     */
    Buffer(Buffer&& other) noexcept : buffer(std::move(other.buffer)),
                                      headCursor(-1),
                                      rollbackCursor(-1) {}
    /**
     * Initialize buffer, copy other buffer data and reset cursor
     */
    Buffer(const Buffer& other) noexcept : buffer(other.buffer),
                                           headCursor(-1),
                                           rollbackCursor(-1) {}

    /**
     * Assignes new buffer to object and resets cursors
     */
    Buffer& operator=(Buffer&& other) noexcept {
      if (this!=&other) {
        buffer = std::move(other.buffer);
        headCursor = -1;
        rollbackCursor = -1;
      }
      return *this;
    }

    /**
     * Assignes new buffer to object and resets cursors
     */
    Buffer& operator=(const Buffer& other) noexcept {
      if (this!=&other) {
        buffer = other.buffer;
        headCursor = -1;
        rollbackCursor = -1;
      }
      return *this;
    }
      
    /**
     * Assignes new string to buffer and resets cursors
     */
    Buffer& operator=(const std::string& other) {
      buffer = other;
      headCursor = -1;
      rollbackCursor = -1;
      return *this;
    }

    /**
     * Assignes new cstring to buffer and resets cursors
     */
    Buffer& operator=(const char* other) {
      buffer = other;
      headCursor = -1;
      rollbackCursor = -1;
      return *this;
    }

    /**
     * Increments string
     *
     * This will not modify the cursors
     */
    Buffer& operator+=(const std::string& other) {
      buffer += other;
      return *this;
    }

    /**
     * Increments string
     *
     * This will not modify the cursors
     */
    Buffer& operator+=(const char* other) {
      buffer += other;
      return *this;
    }

      
    /**
     * Get char at head cursor position
     *
     * If cursor is -1 nullopt is returned
     */
    std::optional<char> current() {
      if (headCursor>-1)
        return buffer[headCursor];
      else
        return std::nullopt;
    }
      
    /**
     * Increment head cursor and get char at new position
     *
     * If cursor is out of bound (no more data is on the buffer) nullopt is returned
     * Cursor is not incremented if the next cursor would be out of bound
     */
    std::optional<char> next() {
      int nextCursor = headCursor+1;
      if (nextCursor<int(buffer.size()))
        return buffer[headCursor=nextCursor];
      else
        return std::nullopt;
    }

    /**
     * Rollback head cursor to latest commit (or -1 if there was no commit)
     */
    Buffer& rollback() {
      headCursor = rollbackCursor;
      return *this;
    }

    /**
     * Create commit point
     *
     * Sets rollback cursor to head cursor
     */
    Buffer& commit() {
      rollbackCursor = headCursor;
      return *this;
    }

    /**
     * Set head cursor to -1
     */
    Buffer& reset() {
      headCursor = -1;
      return *this;
    }

    /**
     * Set head cursor to position. If pos is out of range, false is returned
     * and the cursor is not changed
     */
    bool set(int newpos) {
      if (newpos<int(buffer.size()) && newpos>=-1) {
        headCursor = newpos;
        return true;
      } else
        return false;
    }

    /**
     * Increment head cursor by the specified amount. If the cursor is out of range, false is returned
     * and the cursor is not changed
     */
    bool increment(int update) {
      int nextCursor = headCursor+update;
      if (nextCursor<int(buffer.size()) && nextCursor>=-1) {
        headCursor = nextCursor;
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
     * Insert a array of unsigned chars to the end of the buffer
     */
    Buffer& insert(unsigned char* begin, unsigned char* end) {
      buffer.insert(buffer.end(), begin, end);
      return *this;
    }

    /**
     * Insert a array of unsigned chars to the end of the buffer
     */
    Buffer& insert(const char* begin, const char* end) {
      buffer.insert(buffer.end(), begin, end);
      return *this;
    }
      
    /**
     * Get reference to underlying cstring from index 0
     *
     * Note that regular C-style operations will not work as expected if the underlying data
     * is not strictly string data (if it can contain \0)
     */
    const char* cstr() {
      return buffer.c_str();
    }

    /**
     * Get copy of the underlying string from index 0
     */
    std::string str() {
      return buffer;
    }

    /**
     * Get copy of the underlying data from index 0
     */
    std::vector<unsigned char> vec() {
      return std::vector<unsigned char>(buffer.begin(), buffer.end());
    }

    /**
     * Returns the size of the buffer from index 0
     */
    int size() {
      return buffer.size();
    }

    /**
     * Get reference to underlying cstring from the head cursor
     *
     * Note that regular C-style operations will not work as expected if the underlying data
     * is not strictly string data (if it can contain \0)
     *
     * If cursor is on -1 the 0-index ptr is returned
     */
    const char* cstrAfterCursor() {
      if (headCursor>-1)
        return &buffer[headCursor];
      else
        return &buffer[0];
    }

    /**
     * Get copy of the underlying string from the head cursor (head cursor included)
     *
     * If cursor is on -1 the string from 0 to end is returned
     */
    std::string strAfterCursor() {
      if (headCursor>-1)
        return std::string(buffer.begin()+headCursor, buffer.end());
      else
        return std::string(buffer.begin(), buffer.end());
    }

    /**
     * Get copy of the underlying string from index 0 to head cursor (head cursor included)
     *
     * If cursor is on -1 an empty string is returned
     */
    std::string strBeforeCursor() {
      if (headCursor>-1)
        return std::string(buffer.begin(), buffer.begin()+headCursor+1);
      else
        return "";
    }

    /**
     * Get copy of the underlying data from the head cursor (head cursor included)
     *
     * If cursor is on -1 the data from 0 to end is returned
     */
    std::vector<unsigned char> vecAfterCursor() {
      if (headCursor>-1)
        return std::vector<unsigned char>(buffer.begin()+headCursor, buffer.end());
      else
        return std::vector<unsigned char>(buffer.begin(), buffer.end());
    }

    /**
     * Get copy of the underlying data from index 0 to head cursor (head cursor included)
     *
     * If cursor is on -1 an empty array is returned
     */
    std::vector<unsigned char> vecBeforeCursor() {
      if (headCursor>-1)
        return std::vector<unsigned char>(buffer.begin(), buffer.begin()+headCursor+1);
      else
        return {};
    }

    /**
     * Erases the buffer from index 0 to head cursor (head cursor included)
     *
     * This will also move the head cursor to -1 and commit this change
     * (after the operation the cursor is essentially on the same element as before)
     *
     * Incrementing the offset will make it erase more data of the right side of the cursor
     *
     * If cursor is on -1 (after offset is applied) data is erased from 0 to 0 (no data is erased)
     */
    Buffer& eraseBeforeCursor(uint offset=0) {
      // Create the index, up to which the data will be erased
      int index = headCursor+offset;
      // Check if in upper bounds
      if (index>int(buffer.size()))
        // If size exceeded, cap index to buffer size
        index = buffer.size();
      // Erase data
      buffer.erase(buffer.begin(), buffer.begin()+index+1);
      // Set and commit cursor to 0
      set(-1);
      commit();
      return *this;
    }

    /**
     * Erases the buffer from head cursor (head cursor included)
     *
     * This will also move the head cursor one position back and commit this change
     * (after the operation the cursor is at the last valid element in the buffer)
     *
     * Incrementing the offset will make it erase more data of the left side of the cursor
     *
     * If cursor is on -1 (or gets there by incrementing the offset) data is erased from 0 to end
     */
    Buffer& eraseAfterCursor(uint offset=0) {
      // Create the index, after which the data will be erased
      int index = headCursor-offset;
      // Check if in bounds
      if (index>0)
        // If size exceeded, cap index to 0
        index = 0;
      buffer.erase(buffer.begin()+index, buffer.end());
      // Set cursor to last element
      set(buffer.size()-1);
      commit();
      return *this;
    }
      
    /**
     * Returns the size of the buffer from the head cursor (head cursor included)
     *
     * If cursor is on -1 the size the size of the full buffer (akin to size())
     */
    int sizeAfterCursor() {
      if (headCursor>-1)
        return buffer.size() - headCursor;
      else
        return buffer.size();
    }

    /**
     * Returns the size of the buffer from 0 to head cursor (head cursor included)
     *
     * If cursor is on -1 the size is 0
     */
    int sizeBeforeCursor() {
      return headCursor+1;
    }

  private:
    std::string buffer;
    int headCursor = -1;
    int rollbackCursor = -1;
  };
} // namespace SimpleHTTP::internal::helper


namespace SimpleHTTP {
  
  /**
   * Generic handle wrapper for coroutine
   *
   * Used as return type from coroutines
   *
   * Ensures the underlying coroutine_handle is only attached to one Task
   */ 
  template <typename T>
  class Task {
  public:
    // Define promise type (predefined coroutine struct)
    struct promise_type {
      // Generic return value
      T value;
      // Exception ptr
      std::exception_ptr exception = nullptr;
      // Predefined coroutine function called when creating the coroutine
      Task get_return_object() {
        return Task{std::coroutine_handle<promise_type>::from_promise(*this)};
      }
      // Predefined function called when coroutine is initialized
      // Coroutine is immediately suspended when created
      std::suspend_always initial_suspend() { return {}; }
      // Predefined function called before coroutine is destroyed (value is returned)
      // Suspend finished coroutine, to obtain things like return value / exception from the frame
      // Without suspending the operation after completion, the resources may be cleaned up before reading
      std::suspend_always final_suspend() noexcept { return {}; } 
      // Predefined function called when returning the value (co_return)
      void return_value(T v) { value = v; } // Store return value in promise frame before handle is destroyed
      // Predefined function called when exception is thrown
      void unhandled_exception() { exception = std::current_exception(); } // Store exception to handle it later
    };

    // Default constructor sets coroutine to nullptr
    Task() : coro(nullptr) {}
    // Constructor to initialize handle
    Task(std::coroutine_handle<promise_type> h) : coro(h) {}
    // Destructor to cleanup handle
    ~Task() { if (coro) coro.destroy(); }

    // Delete copy constructor
    Task(const Task&) = delete;

    // Move constructor explicitly sets the other coroutine to nullptr
    // To prevent double destruction
    Task(Task&& other) noexcept : coro(other.coro) {
      other.coro = nullptr;
    }
      
    // Delete copy assignment
    Task& operator=(const Task&) = delete;

    // Move assignment explicitly sets the other coroutine to nullptr
    // and destroys the local coroutine to prevent double destruction
    Task& operator=(Task&& other) noexcept {
      if (&other!=this) {
        if (coro) coro.destroy();
        coro = other.coro;
        other.coro = nullptr;
      }
      return *this;
    }

    /**
     * Checks if coroutine is done/destroyed
     */
    bool done() {
      return !coro || coro.done();
    }

    /**
     * Resumes execution of the coroutine
     *
     * If the coroutine is suspended, it will return nullopt
     * otherwise the return value is returned
     *
     * Throws a logic_error if coroutine is accessed after its completed
     * Rethrows exception if the coroutine completed with an uncaught exception
     */
    std::optional<T> resume() {
      if (!coro || coro.done()) {
        // Resuming coroutine which is done() is undefined
        throw std::logic_error("Attempt to resume a completed coroutine");
      }
      // Resume coroutine
      coro.resume();
      if (coro.done()) {
        // If coroutine returned, handle return / exception

        // Rethrow exception on exception
        if (coro.promise().exception) {
          rethrow_exception(coro.promise().exception);
        }
        // Return value
        return coro.promise().value;
      } else {
        // Else return nullopt
        return std::nullopt;
      }
    }
  private:
    // Main coroutine handle
    std::coroutine_handle<promise_type> coro;
  };
} // namespace SimpleHTTP
  

namespace SimpleHTTP::internal {

  /**
   * Abstract internal request interface defining members used to manipulate the Request object
   *
   * Not visible to the end user
   */
  class RequestInternal {
  public:
    virtual ~RequestInternal() {}

    // Some getters are defined here and in the external Request object
    // 'cause the eventloop needs them to deserialize dynamically based on the values already set
    
    /**
     * Get HTTP method (e.g. GET, POST)
     */
    virtual std::string getMethod() const noexcept = 0;

    /**
     * Get HTTP path/route (e.g. /api/some)
     */
    virtual std::string getPath() const noexcept = 0;

    /**
     * Get HTTP version (e.g. HTTP/1.1)
     */
    virtual std::string getVersion() const noexcept = 0;
    
    /**
     * Set HTTP method (e.g. GET, POST) to the request
     */
    virtual RequestInternal& setMethod(std::string newmethod) = 0;

    /**
     * Set HTTP path to the request
     */
    virtual RequestInternal& setPath(std::string newpath) = 0;

    /**
     * Set HTTP version to the request
     */
    virtual RequestInternal& setVersion(std::string newversion) = 0;

    /**
     * Set a header to the request
     *
     * Key is converted to lowercase
     */
    virtual RequestInternal& setHeader(std::string key, std::string value) = 0;
  };
} // namespace SimpleHTTP::internal


namespace SimpleHTTP {

  /**
   * Abstract external request interface defining members used to inspect the Request object
   */
  class Request {
  public:
    virtual ~Request() {};
    /**
     * Get HTTP method (e.g. GET, POST)
     */
    virtual std::string getMethod() const noexcept = 0;

    /**
     * Get HTTP path/route (e.g. /api/some)
     */
    virtual std::string getPath() const noexcept = 0;

    /**
     * Get HTTP version (e.g. HTTP/1.1)
     */
    virtual std::string getVersion() const noexcept = 0;

    /**
     * Get Content-Length header as integer
     *
     * If no valid content-length is set, nullopt is returned
     */
    virtual std::optional<int> getContentLength() = 0;

    /**
     * Get Transfer-Encoding header as list of encodings (e.g. [ gzip, chunked ])
     *
     * If no valid transfer-encoding header is set, nullopt is returned
     */
    virtual std::optional<std::unordered_set<std::string>> getTransferEncoding() = 0;

    /**
     * Get a query parameter from the request
     */
    virtual std::optional<std::string> getQueryParam(std::string key) = 0;

    /**
     * Get a header from the request
     *
     * Key is strictly lowercase
     */
    virtual std::optional<std::string> getHeader(std::string key) = 0;
  };
} // namespace SimpleHTTP



namespace SimpleHTTP::internal {

  /**
   * Request objects internal derivate, implementing members of the internal and external interfaces
   */
  class RequestImpl : public SimpleHTTP::Request, public SimpleHTTP::internal::RequestInternal {
  public:
    
    /**
     * Get HTTP method (e.g. GET, POST)
     */
    std::string getMethod() const noexcept override {
      return method;
    }

    /**
     * Get HTTP path/route (e.g. /api/some)
     */
    std::string getPath() const noexcept override {
      return path;
    }

    /**
     * Get HTTP version (e.g. HTTP/1.1)
     */
    std::string getVersion() const noexcept override {
      return version;
    }

    /**
     * Get Content-Length header as integer
     *
     * If no valid content-length is set, nullopt is returned
     */
    std::optional<int> getContentLength() override {
      auto it = headers.find("content-length");
      if (it == headers.end()) return std::nullopt;

      // Convert value to integer with istringstream
      std::istringstream iss(it->second);
      int length;
      if (iss >> length)
        return length;
      else return std::nullopt;
    }

    /**
     * Get Transfer-Encoding header as list of encodings (e.g. [ gzip, chunked ])
     *
     * If no valid transfer-encoding header is set, nullopt is returned
     */
    std::optional<std::unordered_set<std::string>> getTransferEncoding() override {
      auto it = headers.find("transfer-encoding");
      if (it == headers.end()) return std::nullopt;

      // Convert transfer-encoding to a string set
      auto tokens = parseTransferEncoding(it->second);
      // If no tokens are found return nullopt
      if (tokens.empty()) return std::nullopt;
      return tokens;
    }

    /**
     * Get a query parameter from the request
     */
    std::optional<std::string> getQueryParam(std::string key) override {
      auto it = queries.find(key);
      if (it != queries.end()) {
        return it->second;
      } else
        return std::nullopt;
    }

    /**
     * Get a header from the request
     *
     * Key is strictly lowercase
     */
    std::optional<std::string> getHeader(std::string key) override {
      auto it = headers.find(key);
      if (it != headers.end()) {
        return it->second;
      } else
        return std::nullopt;
    }

    /**
     * Set HTTP method (e.g. GET, POST) to the request
     */
    RequestImpl& setMethod(std::string newmethod) override {
      method = newmethod;
      return *this;
    }

    /**
     * Set HTTP path to the request
     */
    RequestImpl& setPath(std::string newpath) override {
      path = parseQueryParameters(newpath);
      return *this;
    }

    /**
     * Set HTTP version to the request
     */
    RequestImpl& setVersion(std::string newversion) override {
      version = newversion;
      return *this;
    }

    /**
     * Set a header to the request
     *
     * Key is converted to lowercase
     */
    RequestImpl& setHeader(std::string key, std::string value) override {
      // Key & value are converted tolower
      // in order to properly handle those in the internal structure
      
      // Convert key tolower
      transform(key.begin(), key.end(), key.begin(),
        [](unsigned char c){ return tolower(c); }
      );
      // Set kv pair
      headers[key] = value;
      return *this;
    }

  private:
    // HTTP Method (e.g. Get, Post, etc.)
    std::string method;
    // HTTP Path (e.g. /api/some)
    std::string path;
    // HTTP Version (e.g. HTTP/1.1)
    std::string version;

    // HTTP queries
    std::unordered_map<std::string, std::string> queries;
    // HTTP headers
    std::unordered_map<std::string, std::string> headers;
    
    /**
     * Parse transfer encoding header into a string set
     *
     * Returns tokens parsed as string set
     */
    std::unordered_set<std::string> parseTransferEncoding(std::string rawValue) {
      std::unordered_set<std::string> tokens;
      // Create input stream
      std::istringstream iss(rawValue);
      std::string currentItem;
      // Parse Transfer Encodings
      while (getline(iss, currentItem, ',')) {
        // Trim off spaces
        auto start = currentItem.find_first_not_of(" ");
        auto end = currentItem.find_last_not_of(" ");
        // Skip if no regular char was found in the item
        if (start==std::string::npos || end==std::string::npos) continue;
        // Insert slice without spaces 
        tokens.insert(currentItem.substr(start, end - start + 1));
      }
      return tokens;
    }

    
    /**
     * Parse query parameters from url and insert them to the queries map
     *
     * Query params are automatically inserted into the queries map
     *
     * Returns path without query parameters
     */
    std::string parseQueryParameters(std::string path) {
      // Search query indicator
      auto queryPos = path.find('?');
      // If no query indicator is found, the path is not modified
      if (queryPos==std::string::npos) return path;
      // Obtain the new path (query params removed)
      std::string newPath = path.substr(0, queryPos);

      // Obtain the query param string as input stream
      std::istringstream queryStream(path.substr(queryPos+1));

      // Define token buffer
      std::string token;
      // Iterate over every query param (key=value) fragment
      while (getline(queryStream, token, '&')) {
        // Search split character ("=")
        auto splitPos = token.find('=');
        // If split char not found, the fragment is invalid and skipped
        if (splitPos==std::string::npos) continue;

        // Obtain query param key (first substr)
        std::string key = token.substr(0, splitPos);
        // Obtain query param value (second substr)
        std::string value = token.substr(splitPos+1);

        // Move values to the queries map
        queries[std::move(key)] = std::move(value);
      }
      return newPath;
    }
  };
} // namespace SimpleHTTP::internal


namespace SimpleHTTP::internal {

  /**
   * Abstract internal body interface defining members used for the body
   *
   * Not visible to the end user
   */
  class BodyInternal {
  public:
    virtual ~BodyInternal() {}

    /**
     * Set read request to the body
     */
    virtual void setReadRequest(int size, std::vector<unsigned char>* outBuffer) = 0;
    
    /**
     * Clear read request from the body
     */
    virtual void clearReadRequest() = 0;

    /**
     * Process the read request in the event loop
     */
    virtual bool processRequest() = 0;

    /**
     * Function to drain the body in the event loop
     */
    virtual std::optional<internal::helper::Buffer> drainBody() = 0;
  };
} // namespace SimpleHTTP::internal


namespace SimpleHTTP {

  /**
   * Awaitable structure to schedule read requests
   */
  struct BodyReader {
    internal::BodyInternal& body;
    int size;
    std::vector<unsigned char> outBuffer;

    // Always suspend
    bool await_ready() const noexcept { return false; }

    // Before suspending a new readRequest is created
    void await_suspend(std::coroutine_handle<> h) {
      body.setReadRequest(size, &outBuffer);
    }

    // When resuming, reset the request and return the outBuffer
    std::vector<unsigned char> await_resume() const {
      body.clearReadRequest();
      return outBuffer;
    }
  };

  /**
   * Datastructure defining a request to read a certain amount of data from the body
   */
  struct BodyReadRequest {
    int size;
    std::vector<unsigned char>* outBuffer;
  };

  
  /**
   * Abstract external body interface defining members used to create a readrequest
   *
   * Provides functions to create a awaitable read request (read() / readAll())
   */
  class Body {
  public:
    virtual ~Body() {};

    /**
     * Read a specified amount data from the body
     *
     * Blocks until every the requested data is read
     *
     * This function will return an awaitable and schedules reading to the simplehttp event loop.
     *
     * Use this function inside a coroutine like this: "auto body = co_await readAll();"
     *
     * Returns a vector containing data. If the full body was read an empty vector is returned
     */
    virtual BodyReader read(int size) = 0;

    /**
     * Read all data from the body
     *
     * Blocks until every the full body is read
     *
     * This function will return an awaitable and schedules reading to the simplehttp event loop.
     *
     * Use this function inside a coroutine like this: "auto body = co_await readAll();"
     *
     * Returns a vector containing data. If the full body was read an empty vector is returned
     */
    virtual BodyReader readAll() = 0;
  };
} // namespace SimpleHTTP



namespace SimpleHTTP::internal {
  
  /**
   * Body objects internal derivate, implementing members to process the ReadRequest from internal eventloop
   */
  class BodyImpl : public SimpleHTTP::Body, public SimpleHTTP::internal::BodyInternal {
  public:
    
    /**
     * Read a specified amount data from the body
     *
     * Blocks until every the requested data is read
     *
     * This function will return an awaitable and schedules reading to the simplehttp event loop.
     *
     * Use this function inside a coroutine like this: "auto body = co_await readAll();"
     *
     * Returns a vector containing data. If the full body was read an empty vector is returned
     */
    BodyReader read(int size) override {
      return BodyReader{*this, size};
    }

    /**
     * Read all data from the body
     *
     * Blocks until every the full body is read
     *
     * This function will return an awaitable and schedules reading to the simplehttp event loop.
     *
     * Use this function inside a coroutine like this: "auto body = co_await readAll();"
     *
     * Returns a vector containing data. If the full body was read an empty vector is returned
     */
    BodyReader readAll() override {
      return BodyReader{*this, bodySize};
    }

    
    /**
     * Set read request to the body
     */
    void setReadRequest(int size, std::vector<unsigned char>* outBuffer) override {
      request = BodyReadRequest{size, outBuffer};
    }
    
    /**
     * Clear read request from the body
     */
    void clearReadRequest() override {
      request = std::nullopt;
    }
    
  protected:
    BodyImpl(
      helper::FileDescriptor* socket,
      int socketBufferSize,
      int bodySize,
      helper::Buffer initBuffer
    ) : socket(socket), socketBufferSize(socketBufferSize), bodySize(bodySize), readBuffer(initBuffer) {}
    
    // Socket filedescriptor
    helper::FileDescriptor* socket;
    // Socket buffer size
    int socketBufferSize;
    // Remaining body size (this value is decremented when reading the body)
    int bodySize;
    // Temporary buffer holding the received data
    // Data which is read from the user is erased from this
    helper::Buffer readBuffer;
    // Current pending read request
    std::optional<BodyReadRequest> request;
  };

  
  /**
   * Inherited object to read an HTTP body with a fixed size
   *
   * Overrides functions to handle fixed HTTP bodys (Content-Length: xy)
   */
  class FixedBodyImpl : public SimpleHTTP::internal::BodyImpl {
  public:
    FixedBodyImpl(
      helper::FileDescriptor* socket,
      int socketBufferSize,
      int bodySize,
      helper::Buffer initBuffer
    ) : BodyImpl(socket, socketBufferSize, bodySize, initBuffer) {}
    
    /**
     * Reads the body with a fixed size (HTTP Content-Length header is set)
     *
     * Reads the data requested by the ReadRequest into the outBuffer
     * and updates the bodySize of the Body accordingly
     *
     * Data is read buffered, which means it reads the defined socketBufferSize
     * into the readBuffer and then returns the requested amount of data.
     *
     * Returns true if the requested amount or the full body was read.
     *
     * Returns false if the requested amount was not read but the socket blocks
     *
     * Throws a runtime_error if the connection failed
     */
    bool processRequest() override {
      // If no value is in queue return true to continue      
      if (!request.has_value()) return true;
      BodyReadRequest req = request.value();
      
      // Cap size to body size if size is larger then body
      req.size = req.size>bodySize ? bodySize : req.size;
      
      while (1) {
        // If bodySize is <= 0 an empty vector is returned
        if (bodySize<=0) {
          *req.outBuffer = {};
          return true;
        }
        // Check if readBuffer contains enough data
        if (readBuffer.size() >= req.size) {
          // Set cursor to requested index + 1 (requested size)
          readBuffer.set(req.size-1);
          
          // Copy the requested data (0-requested index) to outBuffer
          *req.outBuffer = readBuffer.vecBeforeCursor();
          // Erase the removed data from the buffer
          readBuffer.eraseBeforeCursor();
          // Decrement body size
          bodySize -= req.size;
          return true;
        }

        // Try to load the full socketBufferSize to the readBuffer
        // This avoids underfetching (e.g. if read() is called frequently just for several bytes)
        unsigned char buffer[socketBufferSize];
        int n = recv(socket->getfd(), buffer, socketBufferSize, 0);
        if (n < 1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // If the call block give the control to the event loop
            // The event loop will then continue execution if data is available
            return false;
          } else {
            // Throw exception. The eventloop will close and cleanup the tcp connection
            throw std::runtime_error(strerror(errno));
          }
        }
        // Insert received data to readBuffer
        readBuffer.insert(buffer, buffer+n);
      }
    }

    /**
     * Drains the body by reading all remaining body data
     *
     * Returns overfetched data if the entire body has been read.
     * By draining directly on fixedBody, it discards the data immediately without
     * cycling it through a readBuffer.
     * Therefore, this will always result in an empty buffer on success.
     *
     * Returns nullopt if more data is required and the socket blocks
     *
     * Throws a runtime_error if the underlying connection fails
     */
    std::optional<helper::Buffer> drainBody() override {
      while (1) {
        // If body is fully read, return true to complete cleanup
        if (bodySize<=0) {
          // Return empty buffer as we directly read the data
          return helper::Buffer();
        }
        // Read data into a pseudo buffer
        // Unlike with chunkedBody, the data is not cycling over readBuffer
        // This highly improves performance 
        unsigned char buffer[bodySize];
        int n = recv(socket->getfd(), buffer, bodySize, 0);
        if (n == 0) {
          // If connection was closed by peer, this is unexpected. The eventloop will clean it up
          throw std::runtime_error("Connection closed unexpectedly");
        }
        if (n < 1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // If the call block give the control to the event loop
            // The event loop will then continue execution if data is available
            return std::nullopt;
          } else {
            // Throw exception. The eventloop will close and cleanup the tcp connection
            throw std::runtime_error(strerror(errno));
          }
        }
        // Decrement body size by the read bytes
        bodySize -= n;
      }
    }
  };


  /**
   * Inherited object to read an HTTP body with a dynamic size
   *
   * Overrides functions to handle chunked HTTP bodys (Transfer-Encoding: chunked)
   */
  class ChunkedBodyImpl : public SimpleHTTP::internal::BodyImpl {
  public:
    ChunkedBodyImpl(
      helper::FileDescriptor* socket,
      int socketBufferSize,
      helper::Buffer initBuffer
      // Body size is set to INT_MAX in order that if readAll wants to read all
      // that it reads until the body is fully read
    ) : BodyImpl(socket, socketBufferSize, INT_MAX, initBuffer) {}
    
    /**
     * Reads the body with transfer encoding "chunked"
     *
     * Reads the data requested by the ReadRequest into the outBuffer
     *
     * Data is read buffered, which means it reads the defined socketBufferSize
     * into the readBuffer and then returns the requested amount of data.
     *
     * Returns true if the requested amount or the full body was read.
     *
     * Returns false if the requested amount was not read but the socket blocks
     *
     * Throws a runtime_error if the connection failed or if the transfer-encoding is invalid
     */
    bool processRequest() override {
      // If no value is in queue return true to continue      
      if (!request.has_value()) return true;
      BodyReadRequest req = request.value();

      while (1) {
        // Process data from buffer
        while(1) {
          if (nextChunkSize==0) break;
          if (readChunkState) {
            if (!processChunkData()) {
              break;
            }
          } else {
            if (!processChunkSize()) {
              break;
            }
          }
        }
        
        // Check if rawReadBuffer contains enough data or if the full body was read
        if (rawReadBuffer.size() >= req.size || nextChunkSize==0) {
          // Cap req size to rawReadBuffer size if the full body is read (nextChunkSize==0)
          req.size = req.size > rawReadBuffer.size() ? rawReadBuffer.size() : req.size;
          // Set cursor to requested index (requested size - 1)
          rawReadBuffer.set(req.size-1);
          // Copy the requested data (0-requested index) to outBuffer
          *req.outBuffer = rawReadBuffer.vecBeforeCursor();
          // Erase the removed data from the buffer
          rawReadBuffer.eraseBeforeCursor();
          return true;
        }

        // Try to load the full socketBufferSize to the readBuffer
        // This avoids underfetching (e.g. if read() is called frequently just for several bytes)
        unsigned char buffer[socketBufferSize];
        int n = recv(socket->getfd(), buffer, socketBufferSize, 0);
        if (n == 0)
          // If connection was closed by peer, this is unexpected. The eventloop will clean it up
          throw std::runtime_error("Connection closed unexpectedly");
        if (n < 1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // If the call block give the control to the event loop
            // The event loop will then continue execution if data is available
            return false;
          } else {
            // Throw exception. The eventloop will close and cleanup the tcp connection
            throw std::runtime_error(strerror(errno));
          }
        }

        // Insert received data to readBuffer
        readBuffer.insert(buffer, buffer + n);
      }      
    }

    /**
     * Drains the body by reading all remaining body data
     *
     * Returns overfetched data if the entire body has been read.
     * This is necessary because to efficiently drain the body, data is overfetched from recv().
     * Thus, the data fetched that does not belong to the body is returned.
     *
     * The readBuffer is explicitly moved to omit a buffercopy, this means using the Body afterwards leads
     * to undefined behavior!
     *
     * Returns nullopt if more data is required and the socket blocks
     *
     * Throws a runtime_error if the underlying connection fails
     */
    std::optional<helper::Buffer> drainBody() override {
      while (1) {
        // Process data from buffer
        while(1) {
          if (readChunkState) {
            if (!skipChunkData()) {
              break;
            }
          } else {
            if (!processChunkSize()) {
              break;
            }
          }
        }
        // Check if readBuffer contains enough data or if the full body was read
        if (nextChunkSize==0) {
          return std::move(readBuffer);
        }

        // Try to load the full socketBufferSize to the readBuffer
        unsigned char buffer[socketBufferSize];
        int n = recv(socket->getfd(), buffer, socketBufferSize, 0);
        if (n == 0)
          // If connection was closed by peer, this is unexpected. The eventloop will clean it up
          throw std::runtime_error("Connection closed unexpectedly");
        if (n < 1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // If the call block give the control to the event loop
            // The event loop will then continue execution if data is available
            return std::nullopt;
          } else {
            // Throw exception. The eventloop will close and cleanup the tcp connection
            throw std::runtime_error(strerror(errno));
          }
        }

        // Insert received data to readBuffer
        readBuffer.insert(buffer, buffer + n);
      }
    }

  private:
    // Buffer holding the decoded data
    helper::Buffer rawReadBuffer;
    // Identifier buffer for the parser
    std::string identifier;
    // Character buffer for the parser
    std::optional<char> c;
    // Determines if currently chunk data is read or if the size is read
    bool readChunkState = false;
    // Determines the size of the next chunk (-1 = uninitialized, 0 = full body is read, other = size to read)
    int nextChunkSize = -1;
    // Defines the maximum length of the hexadecimal chunkSize number
    // If the chunkSize number is larger the encoding is considered invalid
    const int maxChunkSizeLength = 5;
    
    /**
     * Reads and parses the chunk size for the next chunk
     *
     * Returns true if the chunkSize was correctly read into nextChunkSize
     *
     * Returns false if more data needs to be in the readBuffer
     *
     * Throws an exception if the input is invalid encoded
     */
    bool processChunkSize() {
      identifier="";
      // Read size for next chunk
      // There is a max size for the chunk to prevent invalid or malicious
      // encoding to starve the performance of the server
      for (int i=0;i<maxChunkSizeLength;i++) {
        if (!(c = readBuffer.next()).has_value()) {
          // Rollback buffer as not enough data is provided to parse the type
          readBuffer.rollback();
          return false;
        }
        // Skip carriage return as termination is based on newline
        if (c.value()=='\r') continue;
        // If newline is read, this indicates the end of the size
        if (c.value()=='\n') {
          // Convert identifier into string with stoi on base 16 (hex)
          // If the identifier cannot be converted stoi throws an error
          // this error will be thrown to the caller of processRequest()
          // which is fine because if the size is Not convertable, it is considered invalid encoding
          nextChunkSize = stoi(identifier, nullptr, 16);
          readChunkState = true;
          readBuffer.commit();
          // If nextchunk is 0, it can immediately break out of the loop
          if (nextChunkSize==0) return false;
          
          return true;
        }
        identifier+=c.value();
      }
      return true;
    }
    
    /**
     * Reads and parses the chunk data
     *
     * Returns true if the chunk data was correctly processed into the rawReadBuffer
     *
     * Returns false if more data needs to be in the readBuffer
     *
     * Throws an exception if the input is invalid encoded
     */
    bool processChunkData() {
      // Check if the readBuffer has enough data for nextChunkSize + CRLF + Current buffered char
      if (nextChunkSize+2+1>readBuffer.sizeAfterCursor()) {
        return false;
      }

      // Eat current char (most likely '\n')
      // As cstrAfterCursor includes the current headCursor, we need to eat the first char
      // of the actual data into the buffers headCursor
      readBuffer.next(); // No need for bound check as it is already checked above

      // Copy data from readBuffer directly to rawReadBuffer
      rawReadBuffer.insert(
        readBuffer.cstrAfterCursor(),
        readBuffer.cstrAfterCursor()+nextChunkSize
      );

      // Update readBuffer cursor (-1 because below the current char is eaten by next())
      readBuffer.increment(nextChunkSize-1);

      // Expect CRLF ('\r' & '\n') after chunk (defined in RFC 7230)
      identifier = "";
      // Read '\r'
      identifier += readBuffer.next().value();
      // Read '\n'
      identifier += readBuffer.next().value();

      // Check if CRLF is present
      if (identifier!="\r\n") {
        throw std::runtime_error("Expected CRLF after chunk");
      }

      // Erase chunk + chunkSize before cursor
      readBuffer.eraseBeforeCursor();

      readChunkState = false;

      return true;
    }

    /**
     * Parses and skips a chunk block of data
     * (akin to processChunkData, but the data is discarded instead of written to rawReadBuffer)
     *
     * Returns true if the chunk data was correctly processed and skipped
     *
     * Returns false if more data needs to be in the readBuffer
     *
     * Throws an exception if the input is invalid encoded
     */
    bool skipChunkData() {
      // Check if the readBuffer has enough data for nextChunkSize + CRLF + current buffered char
      if (nextChunkSize+2+1>readBuffer.sizeAfterCursor()) {
        return false;
      }
      // Update readBuffer cursor (including current buffered char (most likely '\n'))
      readBuffer.increment(nextChunkSize);

      // Expect CRLF ('\r' & '\n') after chunk (defined in RFC 7230)
      identifier = "";
      // Read '\r'
      identifier += readBuffer.next().value();
      // Read '\n'
      identifier += readBuffer.next().value();


      // Check if CRLF is present
      if (identifier!="\r\n") {
        throw std::runtime_error("Expected CRLF after chunk");
      }

      // Erase chunk + chunkSize before cursor
      readBuffer.eraseBeforeCursor();

      readChunkState = false;
      
      return true;
    }
  };
} // namespace SimpleHTTP



namespace SimpleHTTP::internal {
    
  /**
   * Abstract internal response interface defining members used to inspect the Response object
   *
   * Not visible to the end user
   */
  class ResponseInternal {
  public:
    virtual ~ResponseInternal() {}

    /**
     * Get HTTP version (e.g. HTTP/1.1)
     */
    virtual std::string getVersion() const noexcept = 0;

    /**
     * Get HTTP status code (e.g. 200)
     */
    virtual uint getStatusCode() const noexcept = 0;

    /**
     * Get HTTP status reason (e.g. OK)
     */
    virtual std::string getStatusReason() const noexcept = 0;

    /**
     * Get Content-Type header
     *
     * If no valid content-type is set, nullopt is returned
     */
    virtual std::optional<std::string> getContentType() = 0;

    /**
     * Get Date header as time_point from response
     *
     * If no valid date is set, nullopt is returned
     */
    virtual std::optional<std::chrono::system_clock::time_point> getDate() = 0;

    /**
     * Get header from the response
     */
    virtual std::unordered_map<std::string, std::string>& getHeaders() = 0;

    /**
     * Get header to the response
     *
     * If header is not present, nullopt is returned
     */
    virtual std::optional<std::string> getHeader(std::string key) = 0;

    /**
     * Get body from the response
     */
    virtual std::string getBody() = 0;
  };
} // namespace SimpleHTTP::internal



namespace SimpleHTTP {

  /**
   * Abstract external response interface defining members used to manipulate the Response object
   */
  class Response {
  public:
    /**
     * Set HTTP status code (e.g. 200)
     */
    virtual Response& setStatusCode(uint newstatuscode) = 0;
    
    /**
     * Set HTTP status reason (e.g. OK)
     */
    virtual Response& setStatusReason(std::string newstatusreason) = 0;

    /**
     * Set Content-Type header
     */
    virtual Response& setContentType(std::string newcontenttype) = 0;

    /**
     * Set Date header to the response
     */
    virtual Response& setDate(std::chrono::system_clock::time_point newdate) = 0;

    /**
     * Set header to the response
     */
    virtual Response& setHeader(std::string key, std::string newvalue) = 0;

    /**
     * Set Body to the response
     */
    virtual Response& setBody(std::string newbody) = 0;

    /**
     * Append data to the Body of the response
     */
    virtual Response& appendBody(std::string appendbody) = 0;
  };
} // namespace SimpleHTTP


namespace SimpleHTTP::internal {

  /**
   * Response objects internal derivate, implementing members of the internal and external interfaces
   */
  class ResponseImpl : public SimpleHTTP::Response, public SimpleHTTP::internal::ResponseInternal {
  public:
    
    /**
     * Get HTTP version (e.g. HTTP/1.1)
     */
    std::string getVersion() const noexcept override {
      return version;
    }

    /**
     * Get HTTP status code (e.g. 200)
     */
    uint getStatusCode() const noexcept override {
      return statusCode;
    }

    /**
     * Get HTTP status reason (e.g. OK)
     */
    std::string getStatusReason() const noexcept override {
      return statusReason;
    }

    /**
     * Get Content-Type header
     *
     * If no valid content-type is set, nullopt is returned
     */
    std::optional<std::string> getContentType() override {
      auto it = headers.find("Content-Type");
      if (it != headers.end()) {
        return it->second;
      } else
        return std::nullopt;
    }

    /**
     * Get Date header as time_point from response
     *
     * If no valid date is set, nullopt is returned
     */
    std::optional<std::chrono::system_clock::time_point> getDate() override {
      auto it = headers.find("Date");
      if (it == headers.end()) {
        return std::nullopt;
      }

      // Create input stream to parse the time
      std::istringstream iss(it->second);
      tm date_tm = {};
      // Parse from IMF_fixdate
      iss >> std::get_time(&date_tm, "%a, %d %b %Y %H:%M:%S");

      if (iss.fail()) {
        // If it fails return nullopt
        return std::nullopt;
      } else {
        // If succeeded, convert to time_t and the time_t to a time_point
        return std::chrono::system_clock::from_time_t(mktime(&date_tm));
      }
    }

    /**
     * Get header from the response
     */
    std::unordered_map<std::string, std::string>& getHeaders() override {
      return headers;
    }

    /**
     * Get header to the response
     *
     * If header is not present, nullopt is returned
     */
    std::optional<std::string> getHeader(std::string key) override {
      auto it = headers.find(key);
      if (it != headers.end()) {
        return it->second;
      } else
        return std::nullopt;
    }

    /**
     * Get body from the response
     */
    std::string getBody() override {
      return body;
    }

    /**
     * Set HTTP status code (e.g. 200)
     */
    ResponseImpl& setStatusCode(uint newstatuscode) override {
      statusCode = newstatuscode;
      return *this;
    }
    
    /**
     * Set HTTP status reason (e.g. OK)
     */
    ResponseImpl& setStatusReason(std::string newstatusreason) override {
      statusReason = newstatusreason;
      return *this;
    }

    /**
     * Set Content-Type header
     */
    ResponseImpl& setContentType(std::string newcontenttype) override {
      headers["Content-Type"] = newcontenttype;
      return *this;
    }

    /**
     * Set Date header to the response
     */
    ResponseImpl& setDate(std::chrono::system_clock::time_point newdate) override {
      // Convert to time_t
      time_t newdate_t = std::chrono::system_clock::to_time_t(newdate);
      // Convert to GMT
      tm newdate_tm = *gmtime(&newdate_t);

      std::ostringstream oss;
      // Parse to the IMF_fixdate format
      oss << std::put_time(&newdate_tm, "%a, %d %b %Y %H:%M:%S GMT");
      headers["Date"] = oss.str();
      return *this;
    }

    /**
     * Set header to the response
     */
    ResponseImpl& setHeader(std::string key, std::string newvalue) override {
      headers[key] = newvalue;
      return *this;
    }

    /**
     * Set Body to the response
     */
    ResponseImpl& setBody(std::string newbody) override {
      body = newbody;
      headers["Content-Length"] = std::to_string(body.length());
      return *this;
    }

    /**
     * Append data to the Body of the response
     */
    ResponseImpl& appendBody(std::string appendbody) override {
      body += appendbody;
      headers["Content-Length"] = std::to_string(body.length());
      return *this;
    }
    
  private:
    // HTTP Version, constant as simpleHTTP only supports HTTP/1.1
    std::string version = "HTTP/1.1";
    // HTTP Status code, default is 200
    uint statusCode = 200;
    // HTTP Status reason, default is OK
    std::string statusReason = "OK";
    // HTTP headers, default headers are defined
    std::unordered_map<std::string, std::string> headers = {
      {"Content-Length", "0"},
      {"Content-Type", "text/plain"}, 
      {"Server", "simplehttp"}
    };
    // Body represented as string
    std::string body = "";
  };
} // namespace SimpleHTTP::internal



namespace SimpleHTTP::internal {

  
  /**
   * Stage defines various stages for a http connection
   */
  enum Stage {
    REQ, // Request must be handled
    RES, // Response must be handled
    CLEANUP, // Connection must be cleaned up for reuse
    FUNC_INIT, // User defined function must be initialized
    FUNC_PROC, // User defined function must be processed
    FUNC_BODY, // Function blocks and body must be handled
  };
    
  /**
   * ConnectionState holds the state of a http connection
   */
  struct ConnectionState {
    // Socket descriptor
    helper::FileDescriptor fd;
    // Connection stage
    Stage stage;
    // Request buffer
    helper::Buffer reqBuffer;
    // Response buffer
    helper::Buffer resBuffer;
    // Request Implementation object
    std::unique_ptr<RequestImpl> request = std::make_unique<RequestImpl>();
    // Body object (default initialized to nullptr as there is no default constructor)
    std::unique_ptr<BodyImpl> body = nullptr;
    // Response Implementation object
    std::unique_ptr<ResponseImpl> response = std::make_unique<ResponseImpl>();
    // Coroutine (function) frame
    Task<bool> funcHandle;
    // Timeout when the connection is killed
    std::chrono::system_clock::time_point expirationTime;
  };
} // namespace SimpleHTTP::internal


namespace SimpleHTTP {
  
  /**
   * Server Configuration Object
   *
   * Fine-tune the server settings here.
   * If unfamiliar with an option, retain its default value.
   */
  struct ServerConfiguration {
    /**
     * Size of the Send / Recv buffer in bytes
     */
    int sockBufferSize = 8192;
    /**
     * Size of waiting incomming connections before connections are refused
     */
    int sockQueueSize = 16;
    /**
     * Defines the maximum epoll events handled in one loop iteration
     */
    int maxEventsPerLoop = 12;
    /**
     * Defines the maximum size of the header. If exceeded, request will fail
     */
    int maxHeaderSize = 8192;
    /**
     * Connection timeout. If exceeded without any interaction, the connection is closed
     */
    std::chrono::seconds connectionTimeout = std::chrono::seconds(120);
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
    /**
     * Creates a HTTP server object
     */
    Server() : isInitialized(false), isShutdown(false), instanceCount(0) {};

    /**
     * Creates a HTTP server object
     */
    Server(ServerConfiguration config) : config(config), isInitialized(false), isShutdown(false), instanceCount(0) {};

    

    /**
     * Adds a route to the server
     *
     * Method parameter maps to the HTTP method
     *
     * Route parameter maps to the HTTP path
     *
     * Func defines a coroutine which is called on matching requests.
     * The coroutine defined provides a Request, Body, and a Response object.
     *
     * Request / Response:
     * Those objects can be used to analyze and manipulate the request / response.
     *
     * Body:
     * The body object provides a read() and readAll() function; those functions can be used
     * with co_await to read data from the HTTP body.
     *
     *
     * If not all data from the body is read and the Connection header is set to "keep-alive",
     * the body is drained after the request, blocking new incoming requests on this stream
     * until the full body is read.
     *
     * To manually close the stream after the response (even if Connection is set to "keep-alive"),
     * you can use co_return false;
     *
     * co_return true; indicates that the regular flow is continued
     * (connection remains open after the body is drained)
     *
     *
     * Func shall NOT perform any blocking IO operation besides those provided by simplehttp.
     * Performing another blocking IO operation will block the whole HTTP server, not just this function!
     */
    void Route(
      std::string method,
      std::string route,
      std::function<Task<bool>(Request&, Body&, Response&)> func) {
      
      // Convert method toupper
      transform(method.begin(), method.end(), method.begin(),
        [](unsigned char c){ return toupper(c); }
      );

      // Write lock the routeMap
      std::unique_lock<std::shared_mutex> lock(routeMapLock);
      // Insert coroutine
      routeMap[route][method] = func;
    }


    /**
     * Init initializes the HTTP server on a tcp socket
     *
     * This function will prepare the server by binding the socket and starting the listener
     *
     * If an error occurs an exception is thrown
     */
    void Init(std::string unixSockPath) {
      // Ensure server is only initialized once
      bool initialized = false;
      if (!isInitialized.compare_exchange_strong(initialized, true)) {
        throw std::logic_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "initialize", "Server is already initialized"
          )
        );
      }
      
      std::filesystem::create_directories(std::filesystem::path(unixSockPath).parent_path());
      // Clean up socket, errors are ignored, if the socket cannot be cleaned up,
      // it will fail at bind() which is fine
      unlink(unixSockPath.c_str());

      // Initialize core socket
      coreSocket = internal::helper::FileDescriptor(socket(AF_UNIX, SOCK_STREAM, 0));
      if (coreSocket.getfd() < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create socket", strerror(errno)
          )
        );
      }

      // Create exit event descriptor
      exitEvent = internal::helper::FileDescriptor(eventfd(0, 0));
      if (exitEvent.getfd() < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create exit eventfd", strerror(errno)
          )
        );
      }

      // Create sockaddr_un for convenient option setting
      struct sockaddr_un unSockAddr;
      // Clean unSockAddr, 'cause maybe some weird libs
      // still expect it to zero out sin_zero (which C++ does not do by def)
      memset(&unSockAddr, 0, sizeof(struct sockaddr));
      // Set unSockAddr options
      unSockAddr.sun_family = AF_UNIX;
      strcpy(unSockAddr.sun_path, unixSockPath.c_str());

      // Bind unix socket
      int res = bind(coreSocket.getfd(), (struct sockaddr *)&unSockAddr, sizeof(struct sockaddr_un));
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "bind socket", strerror(errno)
          )
        );
      }

      // Apply options and flags to the socket
      ApplyCoreSocketOptions();

      // Start listener on core socket
      res = listen(coreSocket.getfd(), config.sockQueueSize);
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "start listener", strerror(errno)
          )
        );
      }

      // Socket is closed automatically in destructor, because Socket is RAII compatible.      
    }


    /**
     * Init initializes the HTTP server on a tcp socket
     *
     * This function will prepare the server by binding the socket and starting the listener
     *
     * If an error occurs an exception is thrown
     */
    void Init(std::string ipAddr, u_int16_t port) {
      // Ensure server is only initialized once
      bool initialized = false;
      if (!isInitialized.compare_exchange_strong(initialized, true)) {
        throw std::logic_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "initialize", "Server is already initialized"
          )
        );
      }
      // Create sockaddr_in for convenient option setting
      struct sockaddr_in inSockAddr;
      // Clean inSockAddr, 'cause maybe some weird libs
      // still expect it to zero out sin_zero (which C++ does not do by def)
      memset(&inSockAddr, 0, sizeof(struct sockaddr_in));
      // Set inSockAddr options
      inSockAddr.sin_family = AF_INET;
      inSockAddr.sin_port = htons(port);
      
      // Parse IPv4 addr and insert it to inSockAddr
      int res = inet_pton(AF_INET, ipAddr.c_str(), &inSockAddr.sin_addr);
      if (res==0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "addr parsing", "Invalid IP-Address format"
          )
        );
      } else if (res==-1) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "addr parsing", strerror(errno)
          )
        );
      }

      // Initialize core socket
      coreSocket = internal::helper::FileDescriptor(socket(AF_INET, SOCK_STREAM, 0));
      if (coreSocket.getfd() < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create socket", strerror(errno)
          )
        );
      }
      
      // Create exit event descriptor
      exitEvent = internal::helper::FileDescriptor(eventfd(0, 0));
      if (exitEvent.getfd() < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "create exit eventfd", strerror(errno)
          )
        );
      }

      // SO_REUSEADDR = Enable binding TIME_WAIT network ports forcefully
      int opt = 1; // opt 1 indicates that the options should be enabled
      res = setsockopt(coreSocket.getfd(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "set socket options", strerror(errno)
          )
        );
      }

      // Bind socket to specified addr
      res = bind(coreSocket.getfd(), (struct sockaddr *)&inSockAddr, sizeof(struct sockaddr_in));
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "bind socket", strerror(errno)
          )
        );
      }

      // Apply options and flags to the socket
      ApplyCoreSocketOptions();

      // Start listener on core socket
      res = listen(coreSocket.getfd(), config.sockQueueSize);
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "start listener", strerror(errno)
          )
        );
      }

      // Socket is closed automatically in destructor, because Socket is RAII compatible.
    }
    

    /**
     * Serve launches the HTTP server handling
     *
     * It will handle requests from the core listener socket
     *
     * Serve() can be started from multiple threads without additional synchronisation
     * to increase performance.
     *
     * This function will run forever and block the thread, unless:
     * - the server encounters a critical error, it will then throw an exception
     * - the socket is closed (e.g. with Shutdown()), it will then exit without error
     */
    void Serve() {
      // Epoll event instance (responsible for event infrastructure)
      internal::helper::FileDescriptor epollInstance;
      
      {
        // ShutdownLock is locked to ensure that serve() does not start in the shutdown process.
        std::lock_guard<std::mutex> lock(shutdownLock);
        // If server is already shutdown don't start serve()
        if (isShutdown) {
          throw std::logic_error(
            std::format(
              "Failed to start HTTP server ({}):\n{}",
              "start", "Server is already shutdown"
            )
          );
        }

        // Create epoll instance
        epollInstance = internal::helper::FileDescriptor(epoll_create1(0));
        if (epollInstance.getfd() < 0) {
          throw std::runtime_error(
            std::format(
              "Failed to start HTTP server ({}):\n{}",
              "create epoll instance", strerror(errno)
            )
          );
        }
        // Add core socket to epoll instance
        // This is just used to inform the epoll_ctl which events we are interested in
        struct epoll_event coreSockEvent;
        // On core socket we are only interested in readable state, there is no need for any writes to it
        coreSockEvent.events = EPOLLIN;
        coreSockEvent.data.fd = coreSocket.getfd();
      
        int res = epoll_ctl(epollInstance.getfd(), EPOLL_CTL_ADD, coreSocket.getfd(), &coreSockEvent);
        if (res < 0) {
          throw std::runtime_error(
            std::format(
              "Failed to start HTTP server ({}):\n{}",
              "add core socket to epoll instance", strerror(errno)
            )
          );
        }
        
        // Add exit eventfd to epoll instance
        // This is just used to inform the epoll_ctl which events we are interested in
        struct epoll_event exitEventEvent;
      
        // On core socket we are only interested in readable state, there is no need for any writes to it
        exitEventEvent.events = EPOLLIN;
        exitEventEvent.data.fd = exitEvent.getfd();
      
        res = epoll_ctl(epollInstance.getfd(), EPOLL_CTL_ADD, exitEvent.getfd(), &exitEventEvent);
        if (res < 0) {
          throw std::runtime_error(
            std::format(
              "Failed to start HTTP server ({}):\n{}",
              "add exit eventfd to epoll instance", strerror(errno)
            )
          );
        }

        // Increment instance counter after the exitEvent
        // was added to the epoll instance. This is very important
        // so that if the exitEvent is triggered, that it will cause
        // the eventloop to close.
        instanceCount++;

        // Release shutdownLock for eventloop
      }

      // Cleanup function to ensure instance is correctly closed
      auto cleanup = [&]() noexcept {
        // Acquire shutdown lock to synchronize correctly
        std::lock_guard<std::mutex> lock(shutdownLock);
        // Decrement instance counter
        instanceCount--;
        // Notify shutdown process if it is waiting
        shutdownVariable.notify_one();
      };

      try {
        // Run main event loop
        StartEventLoop(epollInstance);
      } catch (...) {
        // Intercept stack unwinding to call instance cleanup function
        cleanup();
        // Rethrow exception to the caller
        throw;
      }
      // Cleanup instance
      cleanup();
    }



    /**
     * Shutdown shuts down the server
     *
     * tcp/unix will shut down gracefully; http will be forcefully closed (no 500 status)
     *
     * Shutdown() will send an exit event to the running server instances
     * and wait/block until all instances are done.
     *
     * After Shutdown() the Server object cannot be used anymore
     *
     * If an error occurs an exception is thrown
     */
    void Shutdown() {
      // Lock shutdownlock to ensure no instance is started while processing shutdown.
      std::unique_lock<std::mutex> lock(shutdownLock);
      
      if (isShutdown) {
        throw std::logic_error(
          std::format(
            "Failed to shutdown HTTP server ({}):\n{}",
            "shutdown", "Server is already shutdown"
          )
        );
      }
      
      // Static constant defining how many times the write() syscall should be retried.
      static const int MAX_RETRIES = 5;
      
      // Dummy variable as event payload
      uint64_t increment = 1;
      int res = 0;
      int retries = 0;
      
      // Most application handle a Shutdown() exception very critical, therefore EINTR && EAGAIN errors
      // are retried MAX_RETRIES-times to avoid an error escalation due to a simple interrupted syscall.
      do {
        res = write(exitEvent.getfd(), &increment, sizeof(uint64_t));
      } while (retries++ < MAX_RETRIES && res<0 && (errno == EINTR || errno == EAGAIN));

      if (res<0) {
        throw std::runtime_error(
          std::format(
            "Failed to shutdown HTTP server ({}):\n{}",
            "write exit event", strerror(errno)
          )
        );
      }

      // After exit event was sent, isShutdown is updated to prevent
      // new instances from beeing launched
      isShutdown = true;

      // Shutdown variable waits until the instance count reaches 0,
      // indicating that all instances are done.
      shutdownVariable.wait(lock, [&]() { return instanceCount <= 0; });
    }

    
  private:
    // Core bsd socket (responsible for establishing connections)
    // The coreSocket is threadsafe due to the underlying FileDescriptor class
    internal::helper::FileDescriptor coreSocket;
    // Exit event descriptor - eventfd (used to exit the runnning event loops)
    // The exitEvent is threadsafe due to the underlying FileDescriptor class
    internal::helper::FileDescriptor exitEvent;
    
    // Server configuration
    // The configuration is threadsafe because it is constant and only mutated on initialization
    const ServerConfiguration config;
    
    // Defines a map in which each key, corresponding to an HTTP path (e.g. "/api/some", 
    // maps to another map. This inner map associates HTTP methods (e.g., "GET") 
    // with their respective handler functions.
    // RouteMap is threadsafe because it is synchronized with the routeMapLock
    std::unordered_map<std::string, std::unordered_map<std::string, std::function<Task<bool>(
      Request&,
      Body&,
      Response&
    )>>> routeMap;
    // Synchronizes the access to the routeMap    
    std::shared_mutex routeMapLock;

    // Atomic bool determining if server is initialized.
    // Ensures that server is not initialized twice.
    std::atomic<bool> isInitialized;

    // Lock used to ensure that no new instance is created
    // on shutdown process.
    std::mutex shutdownLock;
    // Variable used to wait for all instances to exit
    // in shutdown process.
    std::condition_variable shutdownVariable;
    // Variable determining if the server is shutdown.
    // Synchronized with shutdownLock.
    bool isShutdown;
    // Counter for running instances, synchronized with shutdownLock.
    int instanceCount;
    


    

    /**
     * Applies flags and options to the core socket
     * based on the current server and socket state.
     *
     * If an operation fails, it will throw a runtime_error
     */
    void ApplyCoreSocketOptions() {            
      // Set socket recv buffer (should match a regular HTTP package for optimal performance)
      int res = setsockopt(
        coreSocket.getfd(),
        SOL_SOCKET,
        SO_RCVBUF,
        &config.sockBufferSize,
        sizeof(config.sockBufferSize)
      );
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "set socket options", strerror(errno)
          )
        );
      }
      // Set socket send buffer (should match a regular HTTP package for optimal performance)
      res = setsockopt(
        coreSocket.getfd(),
        SOL_SOCKET,
        SO_SNDBUF,
        &config.sockBufferSize,
        sizeof(config.sockBufferSize)
      );
      if (res < 0) {
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "set socket options", strerror(errno)
          )
        );
      }

      // Retrieve current flags
      int sockFlags = fcntl(coreSocket.getfd(), F_GETFL, 0);
      if (res < 0) {
        throw std::runtime_error(
          std::format(
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
        throw std::runtime_error(
          std::format(
            "Failed to initialize HTTP server ({}):\n{}",
            "update socket flags", strerror(errno)
          )
        );
      }
    }

    
    /**
     * Initialize and start simplehttp event loop
     *
     *
     * This function blocks until:
     * - Eventloop was shut down (core socket closed)
     * - Exception occured
     */
    void StartEventLoop(internal::helper::FileDescriptor &epollInstance) {
      // Buffer with list of connection events
      // This is used by the epoll instance to insert the events on every loop
      struct epoll_event conEvents[config.maxEventsPerLoop];

      // Map holding connection state
      // Key is the filedescriptor number of the socket
      // Value is a ConnectionState object which contains information about the connection
      // including a FileDescriptor resource
      //
      // If the map is destructed (e.g. error is thrown),
      // all sockets are closed automatically due to the RAII compatible FileDescriptor in the ConnectionState
      std::unordered_map<int, internal::ConnectionState> conStateMap;

      
      // Start main event loop
      while (1) {
        // Capture current time
        auto now = std::chrono::system_clock::now();
        // Erase all connections where timeout is reached
        for (auto &con : conStateMap) {
          if (con.second.expirationTime<now) conStateMap.erase(con.first);
        }

        // Wait for any epoll event (includes core socket and connections)
        // The -1 timeout means that it waits indefinitely until a event is reported
        int n = epoll_wait(epollInstance.getfd(), conEvents, config.maxEventsPerLoop, -1);
        if (n < 0) {
          throw std::runtime_error(
            std::format(
              "Critical failure while running HTTP server ({}):\n{}",
              "wait for incoming events", strerror(errno)
            )
          );
        }
        
        // Handle events
        for (int i = 0; i < n; i++) {
          
          // If the event is from the exit signal
          if (conEvents[i].data.fd == exitEvent.getfd()) {
            // If an exit signal is received, the eventloop is closed
            // Sockets etc. are RAII compatible, this means just returning is fine,
            // all filedescriptors will be closed and the kernel will handle the teardown process
            return;
          }

          
          // If the event is from the core socket          
          else if (conEvents[i].data.fd == coreSocket.getfd()) {
            // Check if error occured, if yes fetch it and return
            // For simplicity reasons there is currently no http 500 response here
            // instead sockets are closed leading to hangup signal on the client
            if (conEvents[i].events & EPOLLERR || conEvents[i].events & EPOLLHUP) {
              int err = 0;
              socklen_t errlen = sizeof(err);
              // Read error from sockopt
              int res = getsockopt(conEvents[i].data.fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen);
              // If getsockopt failed, return unknown error
              if (res < 0) {
                throw std::runtime_error(
                  std::format(
                    "Critical failure while running HTTP server ({}):\n{}",
                    "error on core socket", "Unknown error"
                  )
                );
              } else {
                // If getsockopt succeeded, return error
                throw std::runtime_error(
                  std::format(
                    "Critical failure while running HTTP server ({}):\n{}",
                    "error on core socket", strerror(err)
                  )
                );
              }
            }

            // Initialize connection
            // If connection was not established correctly, it is skipped
            auto conState = InitializeConnection(epollInstance, conEvents[i]);
            if (conState.has_value()) {
              // Copied because conSocket is moved before map[] overloader
              int conSockfd = conState.value().fd.getfd();
              // Move the state to the conStateMap
              // Local conState object is explicitly marked as rvalue so that it is moved,
              // otherwise the contained FileDescriptor would be cleaned up immediately
              conStateMap[conSockfd] = std::move(conState.value());
            }
          }

          
          // If the event is from a connection
          else {
            // Find ConnectionState object
            auto conStateIter = conStateMap.find(conEvents[i].data.fd);
            if (conStateIter == conStateMap.end()) {
              // If object is not found, try deleting it from epoll as it is
              // from simplehttp considered as "unmanaged".
              epoll_ctl(epollInstance.getfd(), EPOLL_CTL_DEL, conEvents[i].data.fd, nullptr);
              continue;
            }
            // Handle connection, if false is returned, connection is cleaned up
            if (!HandleConnection(conEvents[i], conStateIter->second)) {
              // Erase from map, this will destruct the FileDescriptor which cleans up the socket.
              conStateMap.erase(conStateIter);
              continue;
            };

            // Update epoll interest for the connection, if false is returned, connection is cleaned up
            if (!UpdateEventInterest(epollInstance, conEvents[i], conStateIter->second.stage)) {
              // Erase from map, this will destruct the FileDescriptor which cleans up the socket.
              conStateMap.erase(conStateIter);
              continue;
            };
          }
        }
      }
    }


    /**
     * Initializes a tcp connection
     *
     * Returns a valid connectionState if the connection is established
     *
     * Returns nullopt if the connection could not be established
     */
    std::optional<internal::ConnectionState> InitializeConnection(
      internal::helper::FileDescriptor &epollInstance, struct epoll_event &event) {

      // Prepare accept() attributes
      struct sockaddr conSockAddr;
      socklen_t conSockLen = sizeof(conSockAddr);
      // Accept connections if any (if no waiting connection, it will result will be -1 and is skipped)
      // Socket is immediately wrapped with a FileDescriptor, by this if any further action fails
      // (like e.g. epoll_ctl), the socket will be cleaned up correctly at the end of the scope
      internal::helper::FileDescriptor conSocket(accept(coreSocket.getfd(), &conSockAddr, &conSockLen));
      // On failure return nullopt
      if (conSocket.getfd() < 1) return std::nullopt;

      // Retrieve current socket flags
      int sockFlags = fcntl(conSocket.getfd(), F_GETFL, 0);
      if (sockFlags < 0) return std::nullopt;

      // Add nonblocking flag to the flags
      sockFlags = sockFlags | O_NONBLOCK;

      // Set updated flag
      int res = fcntl(conSocket.getfd(), F_SETFL, sockFlags);
      if (res < 0) return std::nullopt;
      
      // Create conEvent with EPOLLIN interest
      struct epoll_event conEvent;
      conEvent.events = EPOLLIN;
      // Add custom fd to identify the connection
      conEvent.data.fd = conSocket.getfd();
      // Add connection to list of interest on epoll instance
      res = epoll_ctl(epollInstance.getfd(), EPOLL_CTL_ADD, conSocket.getfd(), &conEvent);
      if (res == 0) {
        // Move the socket to the returned ConnectionState
        return internal::ConnectionState{
          // Move filedescriptor from conSocket
          .fd = std::move(conSocket),
          // Set stage to REQ
          .stage = internal::Stage::REQ,
          // Set expiration time
          .expirationTime = std::chrono::system_clock::now() + config.connectionTimeout
        };
      } else return std::nullopt;
    }


    /**
     * Handle ongoing connection based on the epoll_event reported and the associated ConnectionState
     *
     * Returns true if the eventloop can process
     *
     * Returns false to indicate that the connection should be closed (on tcp layer)
     */
    bool HandleConnection(struct epoll_event &event, internal::ConnectionState &state) {

      // Check if underlying connection failed or hangup
      if (event.events & EPOLLERR || event.events & EPOLLHUP) {
        // At the moment I do not see sufficient reason to handle error further
        return false;
      }

      // Capture current time and add it to the connectionTimeout
      state.expirationTime = std::chrono::system_clock::now() + config.connectionTimeout;

      // Handle current stage
      switch (state.stage) {
      case internal::Stage::REQ:
        // Only process if EPOLLIN event is reported
        if (event.events & EPOLLIN)
          // Continue processing request
          // If encountered critical error, just close connection (erase from map)
          return ProcessRequest(state);
        break;
      case internal::Stage::FUNC_BODY:
        // Only process if EPOLLIN event is reported
        if (event.events & EPOLLIN)
          // Continue process body
          // If encountered critical error, just close connection
          return ProcessBody(state);
        break;
      case internal::Stage::RES:
        // Only process if EPOLLOUT event is reported
        if (event.events & EPOLLOUT) {
          // Continue sending response
          // If encountered critical error or explicit close request (Connection: close)
          return ProcessResponse(state);
        }
        break;
      case internal::Stage::CLEANUP:
        // Only process if EPOLLIN event is reported
        if (event.events & EPOLLIN)
          // Continue cleanup (draining the body)
          // If encountered critical error or explicit close request (Connection: close)
          return ProcessCleanup(state);
        break;
      default:
        // Other stages are not invoked by epoll events
        // but through other stages
        break;
      }
      return true;
    }

    /**
     * Updates the epoll event interest for a connection based on the stage of the connection
     *
     * Modifies the event interest list using epoll_ctl.
     * This is crucial to prevent triggering events which are not needed.
     * (e.g. EPOLLOUT event is almost always triggered, but only used while responding)
     *
     * Returns false if the connection should be closed
     */
    bool UpdateEventInterest(
      internal::helper::FileDescriptor &epollSocket,
      struct epoll_event &event,
      internal::Stage &stage) {

      // Switch stages based on their interest (EPOLLIN/EPOLLOUT)
      switch (stage) {
      case internal::Stage::REQ:
      case internal::Stage::FUNC_BODY:
      case internal::Stage::CLEANUP:
        // If event listener is already set to EPOLLIN, skip the modification
        if (event.events & EPOLLIN) return true;
        // Set event to EPOLLIN
        event.events = EPOLLIN;
        break;
      case internal::Stage::RES:
        // If event listener is already set to EPOLLOUT, skip the modification
        if (event.events & EPOLLOUT) return true;
        // Set event to EPOLLOUT
        event.events = EPOLLOUT;
        break;
      default:
        // If stage does not involve direct calls from event loop, skip the modification
        return true;
      }

      // Modify the updated epoll_event
      int res = epoll_ctl(epollSocket.getfd(), EPOLL_CTL_MOD, event.data.fd, &event);
      if (res<0) {
        // When the main-loop runs with a misconfigured event (e.g. EPOLLOUT if EPOLLIN is expected)
        // this will lead to performance starvation immediately, to prevent this, the connection is closed
        // without further handling etc.
        return false;
      } else {
        return true;
      }
    }
    
    /**
     * Process request based on connection state
     *
     * Returns false if the connection should be closed
     */
    bool ProcessRequest(internal::ConnectionState &state) {
      while (1) {
        // We take the socket buffersize to read everything at once (if available)
        char buffer[config.sockBufferSize+1];
        int n = recv(state.fd.getfd(), buffer, config.sockBufferSize, 0);
        if (n < 1) {
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
          // Deserialize request
          bool res = deserializeRequest(state.reqBuffer, *state.request);
          // Check if serialized part before cursor exceeds maxHeaderSize.
          // This check, performed post-serialization, ensures body parts in the buffer
          // don't affect the count, as deserializeRequest won't move the cursor beyond header size.
          if (state.reqBuffer.sizeBeforeCursor()>config.maxHeaderSize) {
            throw std::runtime_error("Header size exceeds defined maximum size");
          }
          // If request is not fully deserialized; continue fetching data
          if (!res) {
            continue;
          }
        } catch (std::exception &e) {
          (*state.response)
            .setStatusCode(400)
            .setStatusReason("Bad Request")
            .setContentType("text/plain")
            .setBody(std::string(e.what())+"\n");
          state.stage = internal::Stage::RES;
          return true;
        }

        // If the request (header) is fully deserialized

        // Analyze transfer encoding
        // Currently only chunked is supported,
        // which means other encodings will return an error to then sender
        bool isChunked = false;
        auto transferEncoding = state.request->getTransferEncoding();
        if (transferEncoding.has_value()) {
          for (auto encoding : transferEncoding.value()) {
            if (encoding=="chunked")
              isChunked = true;
            else {
              (*state.response)
                .setStatusCode(501)
                .setStatusReason("Not Implemented")
                .setContentType("text/plain")
                .setBody("Transfer-Encoding "+encoding+" is not supported\n");
              state.stage = internal::Stage::RES;
              return true;
            }
          }
        }

        // Analyze content length
        // If content length is not specified bodySize is set to 0
        // assuming no body is provided (except if it is chunked)
        
        int bodySize = 0;
        auto contentLength = state.request->getContentLength();
        if (contentLength.has_value()) {
          bodySize = contentLength.value();
        }

        // Erase processed buffer (include current token (which is most likely '\n'))
        state.reqBuffer.eraseBeforeCursor();

        // State reqBuffer is moved into body, as we won't use the buffer anymore,
        // the move will omit copying the underlying data (the body)
        
        if (isChunked)
          // Create body object and move the rest of the reqBuffer to the body readBuffer.
          // ChunkedBody will interpret data chunked
          state.body = std::make_unique<internal::ChunkedBodyImpl>(
            &state.fd, config.sockBufferSize, std::move(state.reqBuffer)
          );
        else
          // Create body object and move the rest of the reqBuffer to the body readBuffer.
          // FixedBody will interpret data with a fixed length
          state.body = std::make_unique<internal::FixedBodyImpl>(
            &state.fd, config.sockBufferSize, bodySize, std::move(state.reqBuffer)
          );
          
        // Start function execution
        return InitializeFunction(state);
      }
    }

    /**
     * Deserializes buffer into request
     *
     * This function works no matter where the buffer cursor is,
     * it parses based on the content of the request members.
     * The function will parse the full buffer into the request.
     *
     * Returns true if the full header is deserialized
     * Returns false if it needs more data to fully deserialize
     * Parsing errors will lead to an exception
     */
    bool deserializeRequest(internal::helper::Buffer &buffer, internal::RequestInternal &request) {
      std::string identifier = "";
      std::optional<char> c;

      // If method is empty, parse it
      if (request.getMethod().empty()) {
        while (1) {
          if (!(c = buffer.next()).has_value()) {
            // Rollback buffer as not enough data is provided to parse the method
            buffer.rollback();
            return false;
          }
          // Read until space
          if (c.value()==' ') {
            // Set method and exit loop
            request.setMethod(identifier);
            // Commit buffer as the identifier was fully parsed
            buffer.commit();
            break;
          }
          identifier += c.value();
        }
      }
      // If path is empty, parse it
      if (request.getPath().empty()) {
        identifier = "";
        while (1) {
          if (!(c = buffer.next()).has_value()) {
            // Rollback buffer as not enough data is provided to parse the path
            buffer.rollback();
            return false;
          }
          // Read until space
          if (c.value()==' ') {
            // Set path and exit loop
            request.setPath(identifier);
            // Commit buffer as the identifier was fully parsed
            buffer.commit();
            break;
          }
          identifier += c.value();
        }
      }
      // If version is empty, parse it
      if (request.getVersion().empty()) {
        identifier = "";
        while (1) {
          if (!(c = buffer.next()).has_value()) {
            // Rollback buffer as not enough data is provided to parse the version
            buffer.rollback();
            return false;
          }
          // Skip carriage return as termination is based on newline
          if (c.value()=='\r') continue;
          // Read until newline
          if (c.value()=='\n') {
            // Set version and exit loop
            request.setVersion(identifier);
            // Commit buffer as the identifier was fully parsed
            buffer.commit();
            break;
          }
          identifier += c.value();
        }
      }

      // Parse headers
      identifier = "";
      while (1) {
        if (!(c = buffer.next()).has_value()) {
          // Rollback buffer as not enough data is provided
          buffer.rollback();
          return false;
        }
        // Skip carriage return as termination is based on newline
        if (c.value()=='\r') continue;
        // If newline is read, this indicates the end of the header
        if (c.value()=='\n') {
          // Commit buffer and exit deserialization
          buffer.commit();
          return true;
        }

        // Read until key value delimiter
        if (c.value()==':') {
          if (!(c = buffer.next()).has_value()) {
            buffer.rollback();
            return false;
          }
          // Expect ' ' after ':'
          if (c.value()!=' ') {
            throw std::runtime_error(
              "Expected space (' ') character after colon (':'). Got " + std::to_string(c.value())
            );
          }
          
          // Read value
          std::string value = "";
          while (1) {
            if (!(c = buffer.next()).has_value()) {
              buffer.rollback();
              return false;
            }

            // Skip carriage return as termination is based on newline
            if (c.value()=='\r') continue;
            // If newline is read, this indicates the end of this header
            if (c.value()=='\n') {
              // Set header
              request.setHeader(identifier, value);
              // Reset identifier
              identifier = "";
              // Commit and exit loop
              buffer.commit();
              break;
            }
            value += c.value();
          }
        } else
          identifier += c.value();
      }
    }

    /**
     * Initialize user defined function (coroutine)
     *
     * This step involves initial processing of the function
     *
     * Returns false if the connection should be closed
     */
    bool InitializeFunction(internal::ConnectionState &state) {
      {
        // Read lock the routeMap
        std::shared_lock<std::shared_mutex> lock(routeMapLock);
        // Find route
        auto routeIter = routeMap.find(state.request->getPath());
        if (routeIter == routeMap.end()) {
          (*state.response)
            .setStatusCode(404)
            .setStatusReason("Not Found")
            .setContentType("text/plain")
            .setBody("The requested resource "+state.request->getPath()+" was not found on this server\n");
          state.stage = internal::RES;
          return true;
        }
        // Find type / method on the route
        auto handlerIter = routeIter->second.find(state.request->getMethod());
        if (handlerIter == routeIter->second.end()) {
          (*state.response)
            .setStatusCode(405)
            .setStatusReason("Method Not Allowed")
            .setContentType("text/plain")
            .setBody("The method '"+state.request->getMethod()+"' is not allowed for the requested resource\n");
          state.stage = internal::RES;
          return true;
        }

        // Create function handle
        // Coroutine is immediately suspended due to the promise which uses suspend_always as initial_suspend
        state.funcHandle = handlerIter->second(*state.request, *state.body, *state.response);
      }
      
      // Directly start processing coroutine
      return ProcessFunction(state);
    }
    
    /**
     * Process user defined function based on connection state
     *
     * Returns false if the connection should be closed
     */
    bool ProcessFunction(internal::ConnectionState &state) {
      // Resume function execution
      // Unhandled exceptions of the function are NOT catched
      // If an exception is thrown in the user defined function it is thrown to the caller of Serve()
      auto res = state.funcHandle.resume();

      if (res.has_value()) {
        // If has value, the function returned
        if (res.value()) {
          // If returned successful set stage to response
          state.stage = internal::Stage::RES;
          return true;
        } else {
          // If false is returned, the TCP connection is closed after the response.
          // This can be beneficial when a large unread body is provided by the client,
          // avoiding the need to drain the body and potentially increasing performance.
          // Set connection header to close, this will close the tcp socket
          state.request->setHeader("connection", "close");
          state.stage = internal::Stage::RES;
          return true;
        }
      } else {
        // If no value was provided, the function blocks
        state.stage = internal::Stage::FUNC_BODY;
        // Immediately try to process body
        return ProcessBody(state);
      }
    }

    /**
     * Process body reader request which blocks the user defined function
     *
     * Returns false if the connection should be closed
     */
    bool ProcessBody(internal::ConnectionState &state) {
      try {
        // Handle pending request
        if (state.body->processRequest()) {
          // If the request processor returns true, coroutine can be resumed
          state.stage = internal::Stage::FUNC_PROC;
          return ProcessFunction(state);
        } else {
          // If the request processor returns false it needs to read more data
          // In order to do this, the stage remains FUNC_BODY and is processed in the next event loop
          return true;
        }
      } catch (std::exception &e) {
        // Exception occured on reading body
        (*state.response)
          .setStatusCode(400)
          .setStatusReason("Bad Request")
          .setContentType("text/plain")
          .setBody("Invalid body encoding. "+std::string(e.what())+"\n");
        state.stage = internal::Stage::RES;
        return true;
      }
    }

    /**
     * Process response based on connection state
     *
     * Returns false if the connection should be closed
     */
    bool ProcessResponse(internal::ConnectionState &state) {
      if (state.resBuffer.empty()) {
        // Set date header to now
        state.response->setDate(std::chrono::system_clock::now());
        // Serialize response
        serializeResponse(*state.response, state.resBuffer);
      }
      while(1) {
        int n = send(
          state.fd.getfd(),
          state.resBuffer.cstrAfterCursor(),
          state.resBuffer.sizeAfterCursor(), 0
        );
        if (n < 1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Skip if no data is available to read
            return true;
          } else {
            // Exit and close connection on error
            return false;
          }
        }
        // Increment res buffer by the read bytes
        state.resBuffer.increment(n);
        // Check if all data is sent, if yes the operation is finished
        // 'cause sizeAfterCursor includes the cursor, 1 means everything is processed
        if (state.resBuffer.sizeAfterCursor() <= 1) {
          if (state.request->getHeader("connection")=="close") {
            // If connection header is set to "close". Explicitly close the connection
            return false;
          } else {
            // If connection is set to keep-alive, drain the body (if not already done).
            state.stage = internal::Stage::CLEANUP;
            return ProcessCleanup(state);
          }
        }
      }
    }

    /**
     * Serializes response into buffer
     *
     * Unlike the deserialization function, this will serialize the full response into the buffer
     * at once.
     */
    void serializeResponse(internal::ResponseInternal &response, internal::helper::Buffer &buffer) {
      // Initialize buffer with status line 
      buffer =
        std::format(
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
        buffer += std::format(
          "{}: {}\r\n",
          header.first,
          header.second
        );
      }

      // Append body to the buffer
      buffer += std::format(
        "\r\n{}",
        response.getBody()
      );
    }

    /**
     * Process cleanup of the connection if it is reused afterwards (keep-alive enabled)
     *
     * Returns false if the connection should be closed
     */
    bool ProcessCleanup(internal::ConnectionState &state) {
      if (!state.body) {
        // If no body processor is attached (e.g. on critical errors before processing function)
        // tcp connection is closed immediately as the request cannot be drained
        return false;
      }
      try {
        // Continue draining body
        // If draining the body overfetches data from the socket
        // this data is stored to the overfetchBuffer
        // and moved to the new ConnectionStates reqBuffer
        auto overfetchBuffer = state.body->drainBody();
        if (overfetchBuffer.has_value()) {
          // If body is fully cleared,
          // reset connection state by creating a new object and moving the fd
          // The overfetched buffer is moved to the reqBuffer
          state = internal::ConnectionState{
            // Move filedescriptor from old filedescriptor
            .fd = std::move(state.fd),
            // Set stage to REQ
            .stage = internal::Stage::REQ,
            // Add overfetched buffer
            .reqBuffer = overfetchBuffer.value(),
            // Set expiration time
            .expirationTime = std::chrono::system_clock::now() + config.connectionTimeout
          };
          return true;
        } else {
          // If body is not fully cleared,
          // keep connection setup to continue draining the body when more data is available
          return true;
        }
      } catch (std::exception &_) {
        // Exception occured while draining body
        // Close underlying connection
        return false;
      }
    }
  };
} // namespace SimpleHTTP

#endif
