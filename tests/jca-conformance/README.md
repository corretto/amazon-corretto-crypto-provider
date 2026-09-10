# JCA/JCE Conformance Testing

This directory holds the harness that runs JDK-provided cryptography conformance
tests against ACCP, to catch behavioral divergence between ACCP and the
JDK-default JCA/JCE providers (SunJCE, SunEC, SunRsaSign, etc.).

Tracking issue: https://github.com/corretto/amazon-corretto-crypto-provider/issues/550

## Why

ACCP registers ahead of the JDK-default providers and overrides many JCA SPIs
(`Cipher`, `Mac`, `MessageDigest`, `Signature`, `KeyFactory`, `KeyPairGenerator`,
`KeyAgreement`, `KeyGenerator`, `SecretKeyFactory`, `KEM`, ...). The JDK ships an
extensive regression suite (`jtreg`) under `test/jdk/.../crypto`,
`test/jdk/.../security` that exercises concrete provider behavior — exception
types, parameter-spec acceptance, key-encoding round-trips, and KAT vectors.
Running those tests with ACCP installed surfaces divergences our own unit tests
don't.

## Layout

```
tests/jca-conformance/
  README.md            -- this file
  run-jtreg.sh         -- driver: build jtreg, fetch tests, run against ACCP
  jdk-tags.txt         -- per-JDK pin: repo + GA tag for the test content
  jtreg-version.txt    -- pinned openjdk/jtreg tag to build the harness from
  jtreg-test-roots.txt -- which test/jdk subtrees to run (JCA-relevant only)
  exclusions/
    common.txt         -- tests excluded on all JDKs
    jdk17.txt          -- tests excluded only on JDK 17
    jdk21.txt          -- tests excluded only on JDK 21
```

## Harness model

`run-jtreg.sh --full`:

1. Resolves the JDK under test (`TEST_JAVA_HOME`) and its major version.
2. Builds `jtreg` from source at the tag pinned in `jtreg-version.txt`
   (`openjdk/jtreg`). No third-party prebuilt binaries.
3. Sparse-checks-out the OpenJDK test content for this JDK major from the repo
   and GA tag pinned in `jdk-tags.txt` (e.g. `openjdk/jdk17u @ jdk-17.0.13-ga`),
   using a partial (`--filter=blob:none`) + sparse + shallow clone so only the
   crypto test subtrees and the jtreg support dirs (`test/lib`,
   `test/jtreg-ext`) are pulled — not the whole JDK source tree. The test set
   genuinely differs per JDK version, which is why each major is pinned
   separately.
4. Builds ACCP (or consumes a prebuilt `AmazonCorrettoCryptoProvider.jar`) and
   installs it at provider priority 1 (see below).
5. Runs jtreg over the roots in `jtreg-test-roots.txt`, minus the tests named in
   the applicable `exclusions/*.txt`, and exits nonzero if any non-excluded test
   fails.

`run-jtreg.sh --smoke` (the default) validates the wiring without the OpenJDK
checkout: it confirms ACCP installs as provider #1 under the JDK under test and
that the config files parse.

### Adding / updating

- **Update test content for a version:** bump its tag in `jdk-tags.txt`.
- **Add a JDK version:** add a line to `jdk-tags.txt` AND a matrix entry in
  `.github/workflows/jca-conformance.yml`.
- **Update the harness:** bump the tag in `jtreg-version.txt`.

### Provider installation

ACCP is installed at provider priority 1 via a generated `java.security`
override passed to every test JVM with `-Djava.security.properties=`.

Important subtlety: a bare `security.provider.1=<ACCP>` does **not** prepend —
it *overwrites* slot 1 (the `SUN` provider on a stock JDK), evicting it. That
breaks JDK-internal `SecureRandom` bootstrap, which needs SUN's legacy `SHA`
(a.k.a. `SHA1`) `MessageDigest` alias that ACCP does not register, surfacing as
`InternalError: SHA-1 not available` on nearly every test. The harness therefore
discovers the JDK's default provider order at runtime and emits a renumbered
list: ACCP at 1, the JDK defaults shifted to 2..N+1, so nothing is evicted and
legacy aliases fall through to SUN.

The native library is self-extracted from `AmazonCorrettoCryptoProvider.jar` by
ACCP's `Loader`, so only the jar needs to be on the (boot)classpath — no
separate `java.library.path` is required.

## Exclusions

A test belongs in an `exclusions/*.txt` file when it fails under ACCP for a
reason we have triaged and accepted. Two categories:

- **Intentional behavioral difference.** ACCP deliberately diverges from the
  JDK-default provider (documented in [`DIFFERENCES.md`](../../DIFFERENCES.md)).
  The exclusion entry MUST reference the relevant section or a tracking issue.
- **Known bug, not yet fixed.** A real ACCP defect we have not addressed. The
  exclusion entry MUST reference a tracking issue so it can be removed once
  fixed.

This keeps CI green while making the backlog of divergences explicit and
reviewable in source. CI fails if a test that is NOT excluded fails, and (once
enabled) if an excluded test unexpectedly passes — so stale exclusions get
flagged.

### Exclusion file format

One test selector per line. Blank lines and lines beginning with `#` are
ignored. Every non-comment line MUST be preceded by a comment giving the
rationale and a link (DIFFERENCES.md section or issue URL):

```
# AES/GCM rejects reusing an IV across encryptions; SunJCE allows it.
# See DIFFERENCES.md "AES-GCM IV reuse".
com/sun/crypto/provider/Cipher/AEAD/GCMIvReuse.java

# BUG: ECDSA signature with a truncated public key throws a different
# exception type than SunEC. https://github.com/corretto/.../issues/NNN
sun/security/ec/SignatureKAT.java
```

The selector is a path relative to the OpenJDK `test/jdk` root, matching the
form jtreg uses in its reports.

## Running locally

```bash
# Smoke (default): validate wiring only. Fast; uses the JDK on PATH (17+).
./tests/jca-conformance/run-jtreg.sh

# Full: build jtreg, fetch the pinned test content, run the suite against ACCP.
# Builds ACCP if no jar is supplied. First run is slow (jtreg build + checkout).
ACCP_JAR=/path/to/AmazonCorrettoCryptoProvider.jar \
  TEST_JAVA_HOME=/path/to/jdk21 \
  ./tests/jca-conformance/run-jtreg.sh --full

# Enumerate failures without failing (used when seeding exclusion lists):
KEEP_GOING=true ./tests/jca-conformance/run-jtreg.sh --full
```

## JCK

Oracle's JCK (and the OpenJDK Community TCK) require a signed access agreement
and cannot be fetched anonymously from CI. Onboarding JCK is tracked separately
in issue #550; once access is provisioned, a sibling `run-jck.sh` will live here
and reuse the same exclusion model. For now this harness covers jtreg only.
