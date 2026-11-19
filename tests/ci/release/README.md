# Release build, signing, and publishing

These scripts back `.github/workflows/release-build.yml`, the manually dispatched workflow that builds,
signs, smoke-tests, and stages ACCP release jars. It runs only on the CodeBuild-hosted runners for
`corretto/amazon-corretto-crypto-provider`; on a fork the jobs queue and never start.

| File | Role |
|---|---|
| `sign.sh` | JCE-signs (`jarsigner`) each platform jar and GPG-signs every jar and the POM, then verifies both |
| `publish.sh` | Uploads a Central Portal bundle as a `USER_MANAGED` deployment, waits for `VALIDATED`, and (with `STAGED_JARS_DIR`) downloads the staged platform jars back and checks they match the bundle |
| `smoke-test.sh` | Runs the smoke tests against one platform jar; shared by the `smoke-test` and `staged-test` jobs |
| `portal_bundle.py` | Assembles the signed files into one Portal bundle per artifact (FIPS and non-FIPS), with checksums. Fails if any file lacks a signature. Runs in place of Gradle on the `sign` runner, which can read the signing secrets |
| `ReleaseSmokeTest.java`, `ReleaseSmokeTestMlKem.java` | Load a signed platform jar as the JCA provider and check it works |
| `signing-key.asc` | Public half of the production GPG key, committed to avoid a keyserver dependency in `sign.sh` |

## Workflow modes

The `signing-keys` input selects what runs:

| Job | `none` | `test` | `release` |
|---|---|---|---|
| `build-linux`: linux x86_64 and aarch64, FIPS and non-FIPS, unsigned | yes | yes | yes |
| `sign`: JCE + GPG sign and verify | skipped | throwaway keys | production keys |
| `sign` builds the FIPS and non-FIPS Portal bundles and uploads each to Portal staging | - | - | yes |
| `smoke-test`: every unsigned platform jar on JDK 17 and 25 | yes | yes | yes |
| `staged-test`: JCE-verify and smoke-test the jars downloaded from Portal staging, on JDK 17 | - | - | yes |
| `delete-staged-artifact`: deletes the staged-jar workflow artifact, even if a staged test failed | - | - | yes |

Signed jars are uploaded as a workflow artifact in exactly one case: `accp-staged-release`, the jars
downloaded back from Portal staging in a `release` run. On a public repo any signed-in GitHub user can
download artifacts, and these are production-signed builds of an unreleased commit. They verify as
official, the signature cannot be recalled, and they can differ byte-for-byte from the version that is
later published. The artifact exists because the aarch64 staged test runs on a different runner from
`sign`, and the alternative is reading the Portal token, which can publish, on that runner. To keep the
exposure short, `delete-staged-artifact` removes it as soon as the staged tests finish, and the artifact
has one-day retention in case that job never runs. Apart from this artifact, the Portal upload is the
only place signed jars leave the `sign` job, and a `USER_MANAGED` deployment is visible only to the
publishing account until someone publishes it.

## What each check covers

| Property | Checked by | Not checked by |
|---|---|---|
| Jar loads as a provider, native library matches the arch, `assertHealthy()` passes | smoke test | |
| Version string and FIPS flag match the build | smoke test | |
| ACCP is provider #1 and serves SHA-256 (known answer) and AES-GCM (round trip) | smoke test | |
| ML-KEM classes load on JDK 17+ | smoke test (`ReleaseSmokeTestMlKem`) | |
| Signing did not corrupt the jar | `staged-test` (smoke-tests the signed, staged jars) | |
| The staged jars are the signed jars | `publish.sh` (sha256 against the bundle) | |
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

- The staged tests run the smoke tests, not the full test suite, on JDK 17 only.
- No check that Oracle JDK accepts the JCE signature. An Oracle JDK leg against the staged jars would cover
  it; running the test-key jar on Oracle JDK and expecting a load failure would show the check is live.
- The smoke matrix covers JDK 17 and 25 only, though the jars target JDK 8. The aarch64 runner fleet has one
  instance, so a wider matrix queues for a long time.
