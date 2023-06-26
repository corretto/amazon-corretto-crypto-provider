# Sample Kotlin-Gradle project using Amazon Corretto Crypto Provider

## Running the tests

 ```bash
 ./gradlew lib:test
 ```

To use the locally built ACCP JAR, use the following command

```bash
 ./gradlew -PaccpLocalJar="../../../build/cmake/AmazonCorrettoCryptoProvider.jar" lib:test
```