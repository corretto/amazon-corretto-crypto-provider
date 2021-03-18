# ACCP Development Guidance
Correctness and code safety are paramount in the Amazon Corretto Crypto Provider.

This guide is designed to provide a quick introduction to the most important (and ACCP-specific) components to help developers find and learn what is most important.
It doesn't provide all information needed to develop ACCP.
This is a living document and we will continue to add lessons learned and other best practice as appropriate.

# Development Principles

In decreasing order of importance:

1. We must be secure.
    Using ACCP must *never* cause an application to be less secure than if it weren't used.
2. Correctness.
    We must _never_ do the wrong thing or return the wrong result.
    Subtle failures are easy to miss and can cause problems.
    When something goes wrong, we should fail obviously and force the error to be properly handled.
3. All logic flows must be designed and explicit.
    This means that there must be no dependencies on undefined behavior (in Java or C++).
    (There is a single exception to this rule. We are permitted to depend on implicit `NullPointerException`s in Java.)
4. Testing ensures correctness.
    1. Known answer and compatibility tests are crucial.
        Because we are implementing standards, we must be compatible with other implementations. Both the default implementation from Java and BouncyCastle are considered acceptable alternatives. (They both have had historical bugs and so both are used to work around issues in the other.)
        When Known Answer Tests from standards are available, we must use them. (Some older tests do not yet meet this standard but compensate with compatibility tests.)
    2. Cryptographic error cases must be checked.
        (While useful, API error cases should be checked but for simple type, null, and related errors, it is acceptable to miss some.)
    3. Different call patterns must be checked.
        Many cryptographic APIs can be called in different ways. These must all be checked.
	  ([`MessageDigest` example](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Utils.java#L297))
5. ACCP must be fast.
    This is one of the primary purposes of ACCP.
    Benchmark your code, find bottlenecks, fix them.
6. Code should be *obviously* correct.
    A developer should be able to look at an implementation and *know* it is correct with minimal reasoning or justification.
    By implication, this means that you shouldn't be clever.
    This principle sometimes needs to be sacrificed to support higher priority tenets. When this happens, we must do the following:
    1. Isolate complexity. (So that only a few methods or a single file is hard to understand.)
    2. Test to prove correctness. (While we must always do this, it is even more critical here.)
    3. Comment to explain exactly what is intended and, when appropriate, why a particular technique was chosen.
    Examples: ([ConstantTime](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/ConstantTime.java) and its [tests](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/tst/com/amazon/corretto/crypto/provider/test/ConstantTimeTests.java), [Janitor](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Janitor.java) and its [tests](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/tst/com/amazon/corretto/crypto/provider/test/JanitorTest.java))
7. New best practices *must* be applied uniformly to the codebase.
    As we extend and improve ACCP, we will create new tools and frameworks to make our code better (cleaner, safer, easier to read, etc.).
    When we do this, we must  go back through the rest of the ACCP codebase to make the same improvements everywhere.
    Historical examples of this include `java_buffer`, `InputBuffer`, `NativeResource`, `raii_env` and others.
    Just because existing code was acceptable when it was written does not mean it is acceptable now.
    Doing this allows us to continually raise the bar on code quality across the project and combat [bit rot](https://en.wikipedia.org/wiki/Software_rot).


# Important and Unique Components
## Java
### Janitor
ACCP never uses [finalizers](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/Object.html#finalize()) due to significant performance problems.
Since we still need to support Java8 for the foreseable future, we have implemented [Janitor](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Janitor.java) as a JDK8+ replacement for the newer (since JDK9) [Cleaner](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/ref/Cleaner.html). When JDK8 is no longer supported we will re-evaluate `Cleaner` to see if it meets our performance requirements. To avoid circular dependency issues, `Janitor` *MUST NOT* depend on any other ACCP resources (directly or indirectly). It must remain entirely self contained.
The canonical example for using `Janitor` is `NativeResource`.

### Loader
The [Loader](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Loader.java) is responsible for bootstrapping the provider and loading the native library. To avoid circular dependencies `Loader` *MUST NOT* depend on any other classes or logic from within ACCP (with the sole exception of `Janitor`.)

### NativeResource
ACCP commonly needs to track pointers to C++ objects (a.k.a., "native resources"). To ensure that they are properly managed, *all* of these pointers must be wrapped in a [NativeResource](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/NativeResource.java) object and all use of the pointer *must* be via the `use` or `useVoid` methods. This provides proper synchronization and cleanup of the resources.

### InputBuffer
Many cryptographic constructs (MACs, Hashes, AEAD decrypt, and Signatures) take in an arbitrarily long input and return a single output at the end.
The [InputBuffer](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/InputBuffer.java) generalizes this flow by letting a specific implementation plug in a few pieces of logic while handling all of the buffering and type-handling logic in a single place.
This is useful because properly joining and splitting inbound data has caused bugs in other libraries (as has proper handling of `ByteBuffers`).

## C++
Whenever possible, we follow the philosophy that [Resource aquisition is initialization](https://en.wikipedia.org/wiki/Resource_acquisition_is_initialization). Whenever possible we will have stack-based objects tracking the lifecycle of heap-based resources. This ensures that when we leave a code-block the destructors will properly clean up the resources, regardless of how we leave the block. This, combined with C++ exceptions, results in a relatively easy to write/read control flow while being confident that we do not leak resources. This means that only the top-level JNI native methods should ever throw Java exceptions. In all cases `goto` should be avoided and throwing a C++ exception should be used for exceptional cases.

Please remember that (unlike Java) all memory management is C++ is manual and it is very easy to leak memory.
Even memory which hasn't been truly "leaked" (because it is being properly tracked by a `NativeResource` object and so will cleaned eventually) can create an out of memory situation.
The issue is that Java has no visibility into the size of native objects.
This means that all `NativeResource` objects appear to be quite small to Java.
If you have a large amount of native memory allocated (enough to create memory pressure on the system), Java cannot know that it needs to run the GC and clean up the (small) `NativeResource` objects to free the potentially large amount of native memory.

### *_auto
Whenever possible, use classes that provide stack-based tracking. These classes have names with the form `*_auto` (ex: `RSA_auto`).

### BigNumObj
`BigNumObj ` is essentially a `*_auto` object for `BN` resources, but with `BN` specific logic attached to make it easier to use.

### java_ex
`java_ex` is a C++ exception which represents a Java exception and can be converted to one (immediately prior to returning to Java) by calling `throw_to_java(JNIEnv*)`

### raii_env 
`raii_env` wraps an instance of `JNIEnv*` and *MUST* always be used (except for calling `java_ex.throw_to_java()`) and *MUST* always be passed by reference.
It's primary purpose is to check invariants around critical regions and prevent coding mistakes by failing hard if `JNIEnv*` is used incorrectly.

### java_buffer
Representation of any sequence of bytes passed in from Java (currently either a `DirectByteBuffer` or a `byte[]`). This does not give direct access to the underlying bytes.

### jni_borrow
Actual representation of bytes from a `java_buffer`. Due to their interactions with the JVM and GC, they should exist for as short a time as possible.
While a `jni_borrow` exists, ACCP may be in a critial region and thus any use of `raii_env` will result in the process aborting.

### jni_string
Represents a `String` object from Java and gives access to the UTF-8 encoded contents.

### SecureBuffer
The `SecureBuffer` represents a fixed-length array of a type (usually `uint8_t`) which will always zero itself upon destruction.

# About JNI (Java Native Interface)
The [Java Native Interface](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/jniTOC.html) (JNI) is a standard way for standard Java code to interact with native code (such as that written in C or C++).
The JNI (specifically version 6.0 as supported by JDK8 and linked above) is a core component of ACCP's implementation as it allows us to connect high-performance implementations in C/C++ with callers from Java.
Unfortunately, JNI development can be tricky. If not done properly, it jeopardizes correctness, stability, and performance .
There are no shortcuts here. [Read the documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/jniTOC.html).
The most important sections of the official guide are:
* [Introduction](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/intro.html)
* [Java Exceptions](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html#java_exceptions)
* [JNI Types and Data Structures](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html)
* [Array Operations](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#array_operations)

## How ACCP uses the JNI
Just as in many other areas of development, there are a wide range of acceptable styles for JNI code.
ACCP has adopted the following guidelines and patterns to make code more efficient as well as easier to write and review.

### Avoid native calls to Java
Crossing the JNI boundary in either direction is expensive. However, crossing it from Native to Java is far worse.
For this reason, avoid calls that interact with `JNIEnv` (or, more properly, `raii_env` in ACCP).
As a result:
* Native code should never touch a Java object
* Native code should never call a Java method
* All parameters to native methods should be either primitives or primitive arrays.
  (Technically, all arrays are Java objects and thus expensive to touch; however this is an unavoidable compromise).
* Logic should use native data structures and only translate from and to Java results at the beginning and end of the top-most methods.
* Native methods should all be `static`.
  While this technically isn't necessary, if they aren't allowed to touch Java objects, then there is no need for them to be passed a reference to `this`.

One result of this design decision is that ACCP's code can be (roughly) divided into four layers.
These are not *currently* formally marked, but that may change in the future.

Each layer from highest level (Java) down:
1. Pure (normal) Java. This layer is called by external (non-ACCP) Java code.
2. Java->Primitive Translation. This layer is written in Java and converts from Java objects to primitives and actually calls the `native` methods.
3. JNI->Native Translation. This layer is written in C++ and converts from JNI objects to native or ACCP implemented structures (such as `java_buffer`).
    This layer is also responsible for translating C++ exceptions thrown by the lowest layer to Java exceptions.
4. Native. This layer is written in C++ and actually does the logic. It should rarely (if ever) directly interact with `JNIEnv`/`raii_env` and should rarely (if ever) throw a Java exception.

### Error Handling
Once a [Java Exception](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html#java_exceptions) has been thrown, there are exceedingly few JNI operations a caller is allowed to perform.
What's more, it is easy to not notice that there is a Java exception pending.
So long as you do not interact with `JNIEnv`/`raii_env` directly, you shouldn't need to worry about Java exceptions as the ACCP objects/methods which use them already have appropriate checks which throw C++ exceptions (specifically `java_ex`) instead.
If you need to throw an exception, it should almost always be a C++ exception and thrown using the `throw_java_ex` or `throw_openssl` methods. (The former is more efficient but the latter MUST be used when the exception is due to an error state reported by OpenSSL.)
If you are throwing a C++ exception then it *must* be an instance of `java_ex`.
(This is correctly done for you by both `throw_java_ex` and `throw_openssl`.)

Openssl has its *own* separate error handling in the form of a thread-local queue.
This has caused bugs in the past where consuming code has not noticed that errors were present on the stack and so later calls incorrectly saw old and irrelevant Openssl errors.
`throw_openssl` correctly checks *and clears* the OpenSSL error queue prior to throwing the C++ exception.
It also will use the OpenSSL provided error message if available.
If there is no OpenSSL error or applicable message, it will use the provided default message.

Making sure that the OpenSSL error queue is empty prior to returning from native code is critical.
This is why *during coverage tests* we enable extra assertions which will terminate the process if any unhandled OpenSSL errors are present.
These assertions are only present during the coverage tests as they can be expensive (especially on multi-threaded systems).

### Critical Regions
There are two different ways to read data from Java arrays and Strings: Copying, or Critical Regions.
* [String Critical methods](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#GetStringCritical_ReleaseStringCritical)
* [Array Critical methods](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#GetPrimitiveArrayCritical_ReleasePrimitiveArrayCritical)

ACCP generally uses critical regions because they are (usually) faster.
When you are in a critical region the JVM (generally) pins the object being handled to a specific memory location and gives you direct access to the underlying data.
This means that the JVM is unable to do many of its memory management functions (as they require moving objects) and is operating essentially in a degraded mode. (No garbage collection, etc.)
So, when you are in a critical region there are exceedingly few operations you can safely do.
Essentially, all you can do is methods which manipulate your critical region until you get out of it.
It is **extremely important** that you do not allocate *any* Java memory (such as creating Java objects, like a Java Exception), call *any* Java methods (which you shouldn't be doing anyway), or take any actions which may block.
It is also **very important** that you don't spend too much time (more than about a millisecond) in a critical region.
If you are concerned that an operation is not reasonably time-bounded, you should probably be sure to release the critical region on a regular basis to ensure the JVM has the opportunity to do needed memory management. (This isn't always achievable when everything is happening within a single atomic cryptographic operation.)
