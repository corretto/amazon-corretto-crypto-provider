# Release build, signing, and publishing

These scripts back `.github/workflows/release-build.yml`, the manually dispatched workflow that builds,
signs, smoke-tests, and stages ACCP release jars. It runs only on the CodeBuild-hosted runners for
`corretto/amazon-corretto-crypto-provider`; on a fork the jobs queue and never start.

| File | Role |
|---|---|
| `sign.sh` | JCE-signs (`jarsigner`) each platform jar and GPG-signs every jar and the POM, then verifies both |
| `publish.sh` | Uploads a Central Portal bundle as a `USER_MANAGED` deployment and waits for `VALIDATED` |
| `ReleaseSmokeTest.java`, `ReleaseSmokeTestMlKem.java` | Load a signed platform jar as the JCA provider and check it works |
| `signing-key.asc` | Public half of the production GPG key, committed to avoid a keyserver dependency in `sign.sh` |

## Workflow modes

The `signing-keys` input selects what runs:

| Job | `none` | `test` | `release` |
|---|---|---|---|
| `build-linux`: linux x86_64 and aarch64, FIPS and non-FIPS, unsigned | yes | yes | yes |
| `sign`: JCE + GPG sign and verify | skipped | throwaway keys | production keys |
| `sign` builds the Portal bundle and uploads it to Portal staging (non-FIPS only) | - | - | yes |
| `smoke-test`: every unsigned platform jar on JDK 17 and 25 | yes | yes | yes |

Signed jars are never uploaded as workflow artifacts. On a public repo any signed-in GitHub user can
download artifacts, and release-signed jars would be production-signed builds of an unreleased commit: they verify as official,
the signature cannot be recalled, and they can differ byte-for-byte from the version that is later
published. The Portal upload is the only place they leave the `sign` job, and a `USER_MANAGED` deployment
is visible only to the publishing account until someone publishes it.

## What each check covers

| Property | Checked by | Not checked by |
|---|---|---|
| Jar loads as a provider, native library matches the arch, `assertHealthy()` passes | smoke test | |
| Version string and FIPS flag match the build | smoke test | |
| ACCP is provider #1 and serves SHA-256 (known answer) and AES-GCM (round trip) | smoke test | |
| ML-KEM classes load on JDK 17+ | smoke test (`ReleaseSmokeTestMlKem`) | |
| Signing did not corrupt the jar | `sign.sh` (`jarsigner -verify`) | smoke test (runs on unsigned jars) |
| JCE signature is present and signed by the expected cert DN | `sign.sh` (`jarsigner -verify`) | smoke test, Portal |
| Oracle JDK trusts the JCE signature | nothing yet | smoke test runs on Corretto only |
| GPG signature verifies | `sign.sh` (`gpg --verify`), then Portal validation | |
| GPG public key is on a public keyserver | Portal validation | |
| Checksums, POM metadata, sources and javadoc jars present | Portal validation | |
| Account owns the `software.amazon.cryptools` namespace | Portal validation | |

The smoke tests check that the build is correct, not that the signature is trusted. They run on Corretto,
and OpenJDK-based JDKs do not check JCE provider signers (`javax.crypto.ProviderVerifier` reads only
`cryptoPerms`), so a self-signed test jar loads the same as a production-signed one. The jar contents do not
depend on the signature, so the smoke tests run on the unsigned build output in every mode, and the
`sign` job waits for them: a build that fails a smoke test is never signed or staged.

Portal validation checks GPG signatures but ignores the JCE signature.

## Known gaps

- The exact bytes that reach Maven Central are not smoke-tested. The plan is to pull them back from the
  Portal staging deployment after it reaches `VALIDATED` and run the smoke matrix on those.
- No check that Oracle JDK accepts the JCE signature. An Oracle JDK leg against the staged jars would cover
  it; running the test-key jar on Oracle JDK and expecting a load failure would show the check is live.
- The smoke matrix covers JDK 17 and 25 only, though the jars target JDK 8. The aarch64 runner fleet has one
  instance, so a wider matrix queues for a long time.
- Only the non-FIPS bundle is uploaded to the Portal. FIPS is a separate deployment and is not wired up.
