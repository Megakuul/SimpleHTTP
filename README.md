# SimpleHTTP

![SimpleHTTP Icon](/simplehttp.svg "SimpleHTTP")

Extremly simple and fast C++ HTTP library.


### Development

In SimpleHTTP everything happens on the `main` branch.
If you work on a PR which takes more then 2 commits, create a feature branch and squash merge it.



All library relevant code is located in the single header file `/src/simplehttp.h`.


#### Examples

In the `example` directory you will find some examples for the use of the library, with corresponding bazel build rules.


You can also use the examples for testing the application during development.


#### Tests

In the `test` directory you will find simple end-to-end tests which are used for automated testing.


Due to the simplicity of SimpleHTTP, there are no unit tests.


#### Code-Completion

For code-completion and documentation, I recommend using *clangd*.
To generate the *compile_commands.json* file there are various options, I recommend to use this tool:

[bazel-compile-commands](https://github.com/kiron1/bazel-compile-commands)

[bazel-compile-commands releases](https://github.com/kiron1/bazel-compile-commands/releases)

With the following command:
```bash
bazel-compile-commands -R c++14=c++23 -R -fno-canonical-system-headers=""
```
