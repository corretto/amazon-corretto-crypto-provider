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
  run-jtreg.sh         -- driver: fetch jtreg, run the JCA subset against ACCP
  jtreg-test-roots.txt -- which test/jdk subtrees to run (JCA-relevant only)
  exclusions/
    common.txt         -- tests excluded on all JDKs
    jdk17.txt          -- tests excluded only on JDK 17
    jdk21.txt          -- tests excluded only on JDK 21
```

## Harness model

`run-jtreg.sh`:

1. Resolves the running JDK's major version and locates the matching pinned
   OpenJDK source tag (jtreg tests live in the JDK source tree, not in a JDK
   install).
2. Downloads the `jtreg` harness binary (pinned version).
3. Builds ACCP (or consumes a prebuilt `AmazonCorrettoCryptoProvider.jar`) and
   puts it on the bootclasspath / classpath so `AmazonCorrettoCryptoProvider`
   can be installed ahead of the default providers via a security-properties
   override.
4. Runs jtreg over the roots listed in `jtreg-test-roots.txt`, minus the
   tests named in the applicable `exclusions/*.txt` files.
5. Emits a JTReport and a machine-readable summary.

### Provider installation

ACCP is installed as the highest-priority provider by appending a
`-Djava.security.properties=` override (see `run-jtreg.sh`). The native library
is self-extracted from `AmazonCorrettoCryptoProvider.jar` by ACCP's `Loader`, so
only the jar needs to be on the classpath — no separate `java.library.path` is
required.

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
# Uses the JDK on PATH (must be 17+). Builds ACCP if no jar is supplied.
./tests/jca-conformance/run-jtreg.sh

# Against a specific prebuilt jar:
ACCP_JAR=/path/to/AmazonCorrettoCryptoProvider.jar ./tests/jca-conformance/run-jtreg.sh
```

## JCK

Oracle's JCK (and the OpenJDK Community TCK) require a signed access agreement
and cannot be fetched anonymously from CI. Onboarding JCK is tracked separately
in issue #550; once access is provisioned, a sibling `run-jck.sh` will live here
and reuse the same exclusion model. For now this harness covers jtreg only.
