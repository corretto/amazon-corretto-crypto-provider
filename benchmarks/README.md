# ACCP Benchmarks

## Running the benchmarks

The benchmarks can use locally built ACCP or published ACCP.
The `lib:jmh` Gradle task runs the benchmarks and generates reports in JSON and HTML.
The reports are saved under `lib/build/results/jmh`.

### Benchmarking published ACCP to Maven

```bash
./gradlew lib:jmh
```

* `-Pfips` flag can be used to use the FIPS artifacts for benchmarking.
* `-PaccpVerion="ACCP_VERSION"` can be used to run benchmarks for a specific version of ACCP

### Benchmarking locally built ACCP

Use `-PaccpLocalJar="PATH_TO_LOCAL_JAR"`:

```bash
 ./gradlew -PaccpLocalJar="../../build/cmake/AmazonCorrettoCryptoProvider.jar" lib:jmh
```
