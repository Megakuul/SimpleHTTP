# SimpleHTTP
---


![SimpleHTTP Icon](/simplehttp.svg "SimpleHTTP")

Extremly simple and basic library to launch a http server.
 



### Development
---

In SimpleHTTP everything happens on the `main` branch.
If you work on a PR which takes more then 2 commits, create a feature branch and squash merge it.



All library relevant code is located in the single header file `/src/simplehttp.h`.


#### Concept
---
![simplehttp flowchart](/flowchart.png)



#### Examples
---
In the `example` directory you will find some examples for the use of the library, with corresponding bazel build rules.


You can also use the examples for testing the application during development.



#### Tests
---
In the `test` directory you will find simple end-to-end tests which are used for automated testing.


Due to the simplicity of SimpleHTTP, there are no unit tests.



#### Naming/Structural concept
---
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
---
For code-completion and documentation, I recommend using *clangd*.
To generate the *compile_commands.json* file there are various options, I recommend to use this tool:

[bazel-compile-commands](https://github.com/kiron1/bazel-compile-commands)

[bazel-compile-commands releases](https://github.com/kiron1/bazel-compile-commands/releases)

With the following command:
```bash
bazel-compile-commands -R c++14=c++23 -R -fno-canonical-system-headers=""
```
