# ACCP Development Guidance
Like all cryptographic implementations, correctness and code-safety is paramount in the Amazon Corretto Crypto Provider.

The purpose of this guide is not to provide all information needed for development within ACCP.
Instead, it is intended to provide a quick introduction to the most important (and ACCP-specific) components to help developers find and learn what is most important.

# Development Principals

In decreasing order of importance:

1. We must be secure.
    Using ACCP must *never* cause an application to be less secure than if it weren't used.
2. Correctness.
    We must _never_ do the wrong thing or return the wrong result.
    Subtle failures are easy to miss and can cause problems.
    When something goes wrong we should fail obviously and force the error to be properly handled.
3. All logic flows must be designed and explicit.
    This means that there must be no dependencies on undefined behavior (in Java or C++).
    (There is a single exception to this rule. We are permitted to depend on implicit `NullPointerException`s in Java.)
4. Testing ensures correctness.
    1. Known answer and compatibility tests are crucial.
        As we are implementing standards, we must be compatible with other implementations. Both the default implementation from Java and BouncyCastle are considered acceptable alternatives. (They both have had historical bugs and so both are used to work around issues in the other.)
        When Known Answer Tests from standards are available, we must use them. (Some older tests do not yet meet this standard but compensate with compatibility tests.)
    2. Cryptographic error cases must be checked.
        (While useful, API error cases should be checked but for simple type, null, and related errors, it is acceptable to miss some.)
    3. Different call patterns must be checked
        Many cryptographic APIs can be called in different ways. These must all be checked.
	  ([`MessageDigest` example](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Utils.java#L297))
5. ACCP must be fast.
    This is one of the primary purposes of ACCP.
    Benchmark your code, find bottlenecks, fix them.
6. Code should be *obviously* correct.
    A developer should be able to look at an implementation and *know* it is correct with minimal reasoning or justification.
    By implication, this means that you shouldn't be clever.
    This principal sometimes needs to be sacrificed to support higher priority tenets. When this happens, we must do the following:
    1. Isolation of complexity. (So that only a few methods or a single file is hard to understand.)
    2. Testing to prove correctness. (While we must always do this, it is even more critical here.)
    3. Comments explaining exactly what is going on.
    Examples: ([ConstantTime](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/ConstantTime.java) and its [tests](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/tst/com/amazon/corretto/crypto/provider/test/ConstantTimeTests.java), [Janitor](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Janitor.java) and its [tests](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/tst/com/amazon/corretto/crypto/provider/test/JanitorTest.java))

# Important and Unique Components
## Java
### Janitor
ACCP never uses [finalizers](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/Object.html#finalize()) due to significant performance problems. Since we still need to support Java8 for the foreseable future, we have implemented [Janitor](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Janitor.java) as a JDK8+ replacement for the newer (since JDK9) [Cleaner](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/ref/Cleaner.html). To avoid circular dependency issues, `Janitor` *MUST NOT* depend on any other ACCP resources (directly or indirectly). It must remain entirely self contained.
The canonical exmaple for using `Janitory` is `NativeResource`.

### Loader
The [Loader](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/Loader.java) is responsible for bootstrapping the provider and loading the native library. To avoid circular dependencies `Loader` *MUST NOT* depend on any other classes or logic from within ACCP (with the sole exception of `Janitor`.)

### NativeResource
ACCP commonly needs to track pointers to C++ objects (a.k.a., "native resources"). To ensure that they are properly managed, *all* of these pointers must be wrapped in a [NativeResource](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/NativeResource.java) object and all use of the pointer *must* be via the `use` or `useVoid` methods. This provides proper synchronization and cleanup of the resources.

### InputBuffer
Many cryptographic constructs (MACs, Hashes, AEAD decrypt, and Signatures) take in an arbitrarily long input and return a single output at the end.
The [InputBuffer](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/InputBuffer.java) generalizes this flow by letting a specific implementation plug in a few pieces of logic while handling all of the buffering and type-handling logic in a single place.
This is useful because properly joining and splitting inbound data has caused bugs in other libraries (as has proper handling of `ByteBuffers`).

## C++
In general, ACCP uses the philosophy that [Resource aquisition is initialization](https://en.wikipedia.org/wiki/Resource_acquisition_is_initialization). Whenever possible we will have stack-based objects tracking the lifecycle of heap-based resources. This ensures that when we leave a code-block the destructors will properly clean-up the resources, regardless of how we leave the block. This, combined with C++ exceptions, results in a relatively easy to write/read control-flow while being confident that we do not leak resources. This means that only the top-level JNI native methods should ever throw Java exceptions. In all cases `goto` should be avoided and throwing a C++ exception should be used for exceptional cases.

### *_auto
There are several objects with names of the form `*_auth` (ex: `RSA_auto`) which provide stack-based tracking of the named resource. These should be used whenever possible.

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