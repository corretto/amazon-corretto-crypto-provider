# Sample Kotlin-Gradle project using Amazon Corretto Crypto Provider

## Running the tests

 ```bash
 ./gradlew lib:test
 ```

Setting the environment variables `ARCH` would make the build script use
different artifacts available on Maven to be used. For example, the following command
uses ARM 64 build for the sample code:

```bash
ARCH=aarch_64 ./gradlew lib:test
```

* If `ARCH` is not set, `x86_64` is used.