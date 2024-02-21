# ACCP Benchmarks

## Running the benchmarks

The benchmarks can use locally built ACCP or published ACCP.
The `lib:jmh` Gradle task runs the benchmarks and generates reports in JSON and HTML.
The reports are saved under `lib/build/results/jmh`.

* `-PincludeBenchmark="INCLUDE_BENCHMARK"` would only run the specified matching benchmarks.
  * `INCLUDE_BENCHMARK` is a regular expression. For example, `CipherReuse|AesKwp` runs these two sets of benchmarks only.

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

### Benchmarking ACCP that is bundled in JDK

Some customers bundle ACCP directly with their JDKs. To run the benchmarks with such a setup,
one can use the following command:

```bash
 ./gradlew -PuseBundledAccp -Dorg.gradle.java.home=<PATH_TO_YOUR_CUSTOM_JDK> lib:jmh
```
