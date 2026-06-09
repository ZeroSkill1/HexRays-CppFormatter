# Hex-Rays C++ Reformatter

This plugin reformats the pseudocode output from Hex-Rays IDA Pro for non-virtual C++ function calls.

![Pseudocode, before and after installing the plugin](./images/beforeafter.png)

It works by taking the pseudocode output as-is from the decompiler, and restructuring the call expression to more closely resemble what the source form of the expression would've looked like (or at least, as close as possible).

For example, turning:
```cpp
v24 = MyNamespace::MyClass::MyFunction(&object);
```
into:
```cpp
v24 = object.MyFunction();
```
In many cases, this will improve readability greatly, especially when functions are grouped using many namespaces in their name.

The plugin automatically enables reformatting for supported calls, but it is possible to toggle it on or off using `Edit -> Plugins -> C++ function call reformatter`.

## Features:
- **No IDB/ctree modification**. This plugin **only** changes the pseudocode *text* before it is rendered.
- Retaining navigation and cross-reference features for the function and the call object (`this`), e.g. it is still possible to navigate to `MyNamespace::MyClass::MyFunction`, as well as to cross-reference it with other calls in the current and other functions in the program.
- Usage of correct call operator (`->` for pointers, `.` otherwise) based on the type of `this`.
- Reformatting decision based on (demangled) function name and call object (`this`) type, e.g. `this` must be `MyNamespace::MyClass` (or a pointer to it) in order to reformat a call to `MyNamespace::MyClass::MyFunction`.
- Support for inheritance (and multi level deep inheritance), e.g. in cases where `class MyParent : MyBase` and a `MyParent` instance is used to call a non-virtual function that is part of `MyBase`. (proper struct definitions are required in order to detect inheritance).
- Detection of casts, whether they are shown or not, even in bad cases of stack reuse, by rewriting the expression to still look somewhat readable
- Detection of the first array element (`array[0]`) as `this` and reformatting from `a::b::func(&array, ...)` to `array[0].func(...)` or `array[0]->func(...)`
- Support for multi-line function call expressions, as is the case when there are many parameters / parameters with long labels.
- Support for basic *function* templates in demangled function names, currently only `a::b::func<...>(...)` can be reformatted to `obj.func<...>(...);`

## TODO:
- Add support for struct returns (by-value), as in these cases, `this` becomes the second parameter
- Rewrite vftable calls to remove extraneous `this` from call expressions like `this->MyVcall(this, ...)` to `this->MyVcall(...)`

## Installation
This plugin is currently developed and tested with IDA Pro version 9.3.260421. Older versions are unsupported and may not work.

Builds are provided for Linux (x64) and Windows (x64) in the Releases section.

Simply copy the .so or .dll file (depending on your OS) into `plugins` in your IDA installation directory.

## Building
Use the [IDA C++ SDK](https://github.com/HexRaysSA/ida-sdk) to build the plugin.

## More code examples

Array element as `this`:

![Array element as call object](./images/extra_example0.png)

Deeper inheritance chain, and function templates.

The inheritance chain in this case is `frd::FriendProtocol` -> `NEX::ClientProtocol` -> `NEX::Protocol`.

![Deeper inheritance chain and function templates](./images/extra_example1.png)

Cast expression due to stack reuse, properly wrapped in parentheses to preserve syntax.

![Cast expression in a case of stack reuse](./images/extra_example2.png)

Multi-line function reformatting due to large number of parameters.

![Multi-line function reformatting](./images/extra_example3.png)

A case where the first element of an array is the call object, properly reformatted to `array[0]`.

![First element of array as call object, reformatted to array element index 0](./images/extra_example4.png)
