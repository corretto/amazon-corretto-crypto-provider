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
* `-PaccpVersion="ACCP_VERSION"` can be used to run benchmarks for a specific version of ACCP

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

## Comparison providers

Most benchmarks sweep a `provider` parameter so you can read ACCP against the alternatives in the
same run. The providers are Bouncy Castle (`BC`), the relevant JDK provider (`SUN`, `SunEC`,
`SunJCE`, `SunRsaSign`), and [OpenSSL Jostle](https://github.com/openssl-projects/openssl-jostle)
(`JSL`), which wraps the OpenSSL library.

Jostle publishes one jar per architecture and no architecture-neutral jar, so the build picks the
`x86_64` or `aarch64` classifier for you. Use `-PjostleVersion="JOSTLE_VERSION"` to benchmark a
version other than the default.

A few benchmarks leave Jostle out because it does not offer the algorithm:

* `MLKEMEncapDecap` needs a `javax.crypto.KEM` service. Jostle exposes ML-KEM encapsulation
  through a `Cipher` and a `KeyGenerator` instead.
* `RsaCipherOneShot` skips the `NoPadding` case. Jostle serves RSA only with PKCS#1 v1.5 or OAEP.

`AesXtsBenchmark`, `AesGcmVsKwp`, `CipherReuse`, and `EcUtilsBenchmark` name their providers in code
rather than sweeping a parameter, so adding a provider there means adding benchmark methods.
