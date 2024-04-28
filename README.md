# SimpleHTTP
---

![SimpleHTTP Icon](/simplehttp.svg "SimpleHTTP")

A minimalistic HTTP server library, complying with basic HTTP/1.1 standards.



This library is designed for basic internal HTTP servers, such as building a Meta API to access meta information internally.



### Features
---

- Basic HTTP header and query parameter parsing
- Non-blocking event loop architecture for efficient connection handling
- Support for chunked Transfer-Encoding
- Dynamic body reading inside handler
- TCP and Unix Socket support
- No external dependencies


 
### Limitations
---

- No TLS support
- No compression
- Limited feature set
- Lacks advanced security measures
- Linux kernel compatibility only



### Example
---

Basic example of how to use the SimpleHTTP server:

```cpp
#include "simplehttp/simplehttp.hpp"

using namespace SimpleHTTP;

vector<string> list;

Server server();

server.Init("0.0.0.0", 8080);

server.Route("POST", "/add", [&](Request &req, Body &body, Response &res) -> Task<bool> {
  auto tokenHeader = req.getHeader("authorization");
  if (!tokenHeader || *tokenHeader!=TOKEN) {
    res
      .setStatusCode(401).setStatusReason("Unauthorized")
      .setContentType("text/plain").setBody("Invalid authorization token provided!\n");
    co_return true;
  }
  
  // Read all data from the body
  vector<unsigned char> data = co_await body.readAll();
  
  // Insert data into the list
  list.push_back(string(data.begin(), data.end()));

  res.setStatusCode(200).setStatusReason("OK");
  co_return true;
});

server.Route("GET", "/get", [&](Request &req, Body &body, Response &res) -> Task<bool> {
  try {
    auto indexParam = req.getQueryParam("index");
    if (!indexParam)
      throw runtime_error("No element index parameter was specified!");
    
    // Convert index string to integer
    int index = stoi(*req.getQueryParam("index"));
      
    // Obtain object from vector
    string item = list.at(index);
      
    res
      .setStatusCode(200).setStatusReason("OK")
      .setContentType("text/plain").setBody(item+"\n");
      
  } catch (exception &_) {
    res
      .setStatusCode(404).setStatusReason("Not Found")
      .setContentType("text/plain").setBody("Element was not found!\n");
  }
  co_return true;
});

server.Serve();
```

You can also find more examples in the `example` directory.


### Compatibility
---

Including the SimpleHTTP header, requires compiling with `C++20` standard or above.


You can enable it in your Bazel build file by adding a flag to the `copts`:

```
cc_binary(
    ...
    copts = ["-std=c++20"],
    ...
)
```

Also ensure that the std lib used supports `<format>` and `<coroutine>` headers. At least those versions are required:

- GCC libstdc++ 13.1
- Clang libc++ 15.0



### Development
---

In SimpleHTTP everything happens on the `main` branch.
If you work on a PR which takes more then 2 commits, create a feature branch and squash merge it.



All library relevant code is located in the single header file `simplehttp/simplehttp.hpp`.


#### Concept

![simplehttp flowchart](/flowchart.png)



#### Examples

In the `example` directory you will find some examples for the use of the library, with corresponding bazel build rules.


You can also use the examples for testing the application during development.



#### Tests

In the `test` directory you will find simple end-to-end tests which are used for automated testing.

Tests are performed with the bazel test runner inside a sandboxed environment.


All tests are based on the `libcurl` http client library.



Due to the simplicity of SimpleHTTP, there are no unit tests.



#### Naming/Structural concept

**Naming concept**


The following name concept is used:

- Variables = camelCase
- Functions = PascalCase
- Classes   = PascalCase

Other types are named according to common sense


*Exception*: Filedescriptor ("fd") may always be written in snake case (e.g. getfd()) because "Fd" looks damn ugly.


**Structural concept**


For clarity, code is split up into namespaces:

| Namespace                        | Description                                                          |
|----------------------------------|----------------------------------------------------------------------|
| **SimpleHTTP**                   | Base namespace, containing code used by the library user             |
| **SimpleHTTP::internal**         | Internal namespace, containing internal code used from the eventloop |
| **SimpleHTTP::internal::helper** | Helper namespace, containing helper functions and classes            |


Another important concept used is the abstraction of the **Request, Body, Response** objects.

These objects essentially use two abstract interfaces, an internal interface (e.g. RequestInternal) used by the 
simplehttp event loop, and an external interface (e.g. Request) that is used by the library user within the defined coroutine.


Both interfaces are inherited by an implementation class (e.g. RequestImpl), which overrides the virtual members.

The reason for this concept/pattern is to hide the internal members of the objects from the library user.



#### Code-Completion

For code-completion and documentation, I recommend using *clangd*.
To generate the *compile_commands.json* file there are various options, I recommend to use this tool:

[bazel-compile-commands](https://github.com/kiron1/bazel-compile-commands)

[bazel-compile-commands releases](https://github.com/kiron1/bazel-compile-commands/releases)

With the following command:
```bash
bazel-compile-commands -R c++14=c++23 -R -fno-canonical-system-headers=""
```
