#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Run the JCA/JCE-relevant subset of the OpenJDK jtreg suite against ACCP.
# See tests/jca-conformance/README.md for the design and the exclusion model.
#
# Modes:
#   --smoke (default)  Validate harness wiring (ACCP installs as provider #1,
#                      config files parse) without checking out the OpenJDK test
#                      tree or running the suite. Fast; no network beyond ACCP.
#   --full             Build jtreg from pinned openjdk/jtreg, sparse-checkout the
#                      pinned per-version OpenJDK test content, and run the
#                      configured JCA test roots against ACCP with the exclusion
#                      lists applied.

set -euo pipefail

#############################################
# Paths and config files
#############################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK_DIR="${WORK_DIR:-${REPO_ROOT}/build/jca-conformance}"

JDK_TAGS_FILE="${SCRIPT_DIR}/jdk-tags.txt"
JTREG_VERSION_FILE="${SCRIPT_DIR}/jtreg-version.txt"
TEST_ROOTS_FILE="${SCRIPT_DIR}/jtreg-test-roots.txt"

MODE="smoke"

usage() {
    cat <<EOF
Usage: $0 [--smoke|--full] [--work-dir DIR]

  --smoke   (default) Validate harness wiring without running the full suite.
  --full    Build jtreg, fetch the pinned OpenJDK test content, and run the
            JCA conformance subset against ACCP.
  --work-dir DIR  Scratch directory (default: ${WORK_DIR}).

Environment:
  ACCP_JAR        Path to a prebuilt AmazonCorrettoCryptoProvider.jar. If unset,
                  the script builds ACCP from this checkout.
  TEST_JAVA_HOME  JDK to test against (default: JAVA_HOME, then \`java\` on PATH).
  KEEP_GOING      If "true", a non-empty set of unexpected failures does not set
                  a nonzero exit (used to enumerate failures when seeding the
                  exclusion lists). Default: false.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --smoke) MODE="smoke"; shift ;;
        --full)  MODE="full";  shift ;;
        --work-dir) WORK_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

#############################################
# Resolve the JDK under test
#############################################
TEST_JAVA_HOME="${TEST_JAVA_HOME:-${JAVA_HOME:-}}"
if [[ -z "${TEST_JAVA_HOME}" ]]; then
    if ! command -v java >/dev/null 2>&1; then
        echo "ERROR: no JDK found. Set TEST_JAVA_HOME or JAVA_HOME, or put java on PATH." >&2
        exit 1
    fi
    TEST_JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
fi
JAVA_BIN="${TEST_JAVA_HOME}/bin/java"

# Parse the `version "X..."` line specifically. Filtering by the `version` token
# skips noise some JVMs print first (e.g. "Picked up JAVA_TOOL_OPTIONS: ...").
JDK_MAJOR="$("${JAVA_BIN}" -version 2>&1 | grep -E 'version "[0-9]' | head -1 | sed -E 's/.*version "([0-9]+).*/\1/')"
if ! [[ "${JDK_MAJOR}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: could not parse JDK major version from '${JAVA_BIN} -version'." >&2
    exit 1
fi
if [[ "${JDK_MAJOR}" -lt 17 ]]; then
    echo "ERROR: ACCP JCA conformance requires JDK 17+; detected major version '${JDK_MAJOR}'." >&2
    exit 1
fi
echo "==> JDK under test: major version ${JDK_MAJOR} (${TEST_JAVA_HOME})"

#############################################
# Resolve / build the ACCP jar
#############################################
resolve_accp_jar() {
    if [[ -n "${ACCP_JAR:-}" ]]; then
        if [[ ! -f "${ACCP_JAR}" ]]; then
            echo "ERROR: ACCP_JAR='${ACCP_JAR}' does not exist." >&2
            exit 1
        fi
        echo "${ACCP_JAR}"
        return
    fi
    local built="${REPO_ROOT}/build/cmake/AmazonCorrettoCryptoProvider.jar"
    if [[ ! -f "${built}" ]]; then
        echo "==> Building ACCP (no ACCP_JAR supplied)..." >&2
        ( cd "${REPO_ROOT}" && ./gradlew build -x test ) >&2
    fi
    echo "${built}"
}

#############################################
# Config-file helpers
#############################################
# Look up "<repo> <tag>" for the current JDK major from jdk-tags.txt.
lookup_jdk_pin() {
    local major="$1" repo tag jdk
    while read -r jdk repo tag; do
        [[ -z "${jdk}" || "${jdk}" == \#* ]] && continue
        if [[ "${jdk}" == "${major}" ]]; then
            echo "${repo} ${tag}"
            return 0
        fi
    done < "${JDK_TAGS_FILE}"
    return 1
}

read_jtreg_tag() {
    grep -vE '^\s*(#|$)' "${JTREG_VERSION_FILE}" | head -1
}

# Merged, comment-stripped exclusion selectors for this JDK.
collect_exclusions() {
    local f
    for f in "${SCRIPT_DIR}/exclusions/common.txt" "${SCRIPT_DIR}/exclusions/jdk${JDK_MAJOR}.txt"; do
        [[ -f "$f" ]] || continue
        grep -vE '^\s*(#|$)' "$f" || true
    done
}

# Comment-stripped jtreg test roots.
collect_test_roots() {
    grep -vE '^\s*(#|$)' "${TEST_ROOTS_FILE}" || true
}

#############################################
# ACCP provider installation via security props
#############################################
# Emits a java.security fragment that installs ACCP as provider #1 AND shifts
# every JDK default provider down by one, so nothing is evicted.
#
# Subtlety: a single 'security.provider.1=ACCP' line does NOT prepend -- it
# OVERWRITES slot 1 (the SUN provider on a stock JDK), evicting it entirely.
# That breaks JDK-internal SecureRandom bootstrap, which needs SUN's "SHA"
# (a.k.a. SHA1) MessageDigest -- a legacy alias ACCP intentionally does not
# register. The symptom is "InternalError: SHA-1 not available" on nearly every
# test. To install ACCP ahead of the defaults without dropping any, we must
# renumber: ACCP at 1, then the JDK's existing providers at 2..N+1.
#
# We discover the JDK's default provider order at runtime (it differs across JDK
# versions) by asking the JDK under test, then emit the renumbered list.
write_accp_security_props() {
    local out="$1" accp_jar="$2"
    local names_src="${WORK_DIR}/ListProviders.java"
    cat > "${names_src}" <<'JAVA'
import java.security.Security;
public class ListProviders {
    public static void main(String[] a) {
        for (var p : Security.getProviders()) System.out.println(p.getName());
    }
}
JAVA
    # Query the *default* provider order with a clean JVM (no ACCP, no override).
    local defaults
    defaults="$("${JAVA_BIN}" "${names_src}" 2>/dev/null)"
    if [[ -z "${defaults}" ]]; then
        echo "ERROR: could not enumerate default security providers." >&2
        exit 1
    fi

    {
        echo "# Generated by run-jtreg.sh: ACCP at priority 1, JDK defaults shifted down."
        echo "security.provider.1=com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider"
        local i=2 name
        while IFS= read -r name; do
            [[ -z "${name}" ]] && continue
            echo "security.provider.${i}=${name}"
            i=$((i + 1))
        done <<< "${defaults}"
    } > "${out}"
}

#############################################
# Build jtreg from pinned openjdk/jtreg
#############################################
build_jtreg() {
    # Echoes the path to the built jtreg home (containing bin/jtreg, lib/jtreg.jar).
    local tag; tag="$(read_jtreg_tag)"
    local src="${WORK_DIR}/jtreg-src"
    local home="${WORK_DIR}/jtreg-${tag}"

    if [[ -x "${home}/bin/jtreg" ]]; then
        echo "${home}"
        return
    fi

    echo "==> Building jtreg ${tag} from openjdk/jtreg" >&2
    rm -rf "${src}"
    git clone --depth 1 --branch "${tag}" https://github.com/openjdk/jtreg.git "${src}" >&2

    # jtreg's build downloads its own dependencies; run its make wrapper. The
    # build needs a JDK >= the one being tested; reuse TEST_JAVA_HOME.
    ( cd "${src}" && bash make/build.sh --jdk "${TEST_JAVA_HOME}" ) >&2

    # The build emits to build/images/jtreg. Stage it under a version-stamped home.
    rm -rf "${home}"
    mv "${src}/build/images/jtreg" "${home}"
    echo "${home}"
}

#############################################
# Sparse-checkout pinned OpenJDK test content
#############################################
fetch_test_content() {
    # Echoes the path to the checked-out OpenJDK source root (containing test/jdk).
    local pin repo tag
    if ! pin="$(lookup_jdk_pin "${JDK_MAJOR}")"; then
        echo "ERROR: no pin for JDK ${JDK_MAJOR} in ${JDK_TAGS_FILE}." >&2
        exit 1
    fi
    repo="${pin%% *}"
    tag="${pin##* }"
    local dest="${WORK_DIR}/openjdk-${JDK_MAJOR}-${tag}"

    if [[ -d "${dest}/test/jdk" ]]; then
        echo "${dest}"
        return
    fi

    echo "==> Sparse-checkout ${repo} @ ${tag} (test content only)" >&2
    rm -rf "${dest}"
    # Partial clone (no blobs) + sparse + shallow: pulls only the blobs for the
    # paths we sparse-set, at the pinned tag. Far lighter than a full clone.
    git clone --filter=blob:none --no-checkout --depth 1 --branch "${tag}" \
        "https://github.com/${repo}.git" "${dest}" >&2
    (
        cd "${dest}"
        git sparse-checkout init --cone
        # Sparse set must include, beyond the crypto test subtrees:
        #   test/jdk          -- the TEST.ROOT marker jtreg keys off of.
        #   test/lib          -- jdk.test.lib.* helper classes that test/jdk's
        #                        TEST.ROOT references via requires.extraPropDefns
        #                        (Platform.java, Container.java) and many tests
        #                        pull in via @library /test/lib.
        #   test/jtreg-ext    -- requires/VMProps.java, the @requires property
        #                        provider TEST.ROOT declares. Without it jtreg
        #                        aborts before running any test.
        # Omitting these makes jtreg fail at startup with "Cannot find file ...
        # for extra property definitions" and produce zero results.
        local roots=() r
        while IFS= read -r r; do roots+=("test/jdk/${r}"); done < <(collect_test_roots)
        git sparse-checkout set "test/jdk" "test/lib" "test/jtreg-ext" "${roots[@]}" >&2
        git checkout "${tag}" >&2
    )
    echo "${dest}"
}

#############################################
# Translate our exclusions into a jtreg exclude-list (.jtx)
#############################################
write_jtx() {
    # jtreg's -exclude:FILE takes lines of "<test-path> <bugid> <description>".
    # Our exclusion files already carry the test path; synthesize the rest.
    local out="$1"
    : > "${out}"
    local sel
    while IFS= read -r sel; do
        [[ -z "${sel}" ]] && continue
        echo "${sel} 0000000 generic-all ACCP-excluded (see tests/jca-conformance/exclusions)" >> "${out}"
    done < <(collect_exclusions)
}

#############################################
# Smoke mode: validate wiring only
#############################################
run_smoke() {
    echo "==> [smoke] Validating harness wiring (no OpenJDK checkout, no test run)."
    mkdir -p "${WORK_DIR}"

    local accp_jar; accp_jar="$(resolve_accp_jar)"
    echo "==> [smoke] ACCP jar: ${accp_jar}"

    write_accp_security_props "${WORK_DIR}/accp.security" "${accp_jar}"

    echo "==> [smoke] Verifying ACCP installs as the highest-priority provider..."
    local src="${WORK_DIR}/AccpSmoke.java"
    cat > "${src}" <<'JAVA'
import java.security.Security;
import java.security.Provider;
public class AccpSmoke {
    public static void main(String[] args) throws Exception {
        Provider p = Security.getProviders()[0];
        String name = p.getName();
        System.out.println("Highest-priority provider: " + name);
        if (!"AmazonCorrettoCryptoProvider".equals(name)) {
            System.err.println("FAIL: expected ACCP to be provider #1, got " + name);
            System.exit(1);
        }
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        if (!"AmazonCorrettoCryptoProvider".equals(md.getProvider().getName())) {
            System.err.println("FAIL: SHA-256 not served by ACCP: " + md.getProvider().getName());
            System.exit(1);
        }
        System.out.println("OK: ACCP installed and serving SHA-256.");
    }
}
JAVA
    "${JAVA_BIN}" -cp "${accp_jar}" \
        -Djava.security.properties="${WORK_DIR}/accp.security" \
        "${src}"

    echo "==> [smoke] Parsing config files..."
    local n; n="$(collect_exclusions | wc -l | tr -d ' ')"
    echo "==> [smoke] ${n} exclusion selector(s) for JDK ${JDK_MAJOR}."
    local roots; roots="$(grep -cvE '^\s*(#|$)' "${TEST_ROOTS_FILE}" || true)"
    echo "==> [smoke] ${roots} jtreg test root(s) configured."
    if ! lookup_jdk_pin "${JDK_MAJOR}" >/dev/null; then
        echo "ERROR: [smoke] no jdk-tags.txt pin for JDK ${JDK_MAJOR}." >&2
        exit 1
    fi
    echo "==> [smoke] JDK ${JDK_MAJOR} pinned to: $(lookup_jdk_pin "${JDK_MAJOR}")"
    echo "==> [smoke] jtreg pinned to: $(read_jtreg_tag)"
    echo "==> [smoke] OK. Harness wiring validated. Use --full to run the suite."
}

#############################################
# Full mode: build jtreg, fetch tests, run
#############################################
run_full() {
    mkdir -p "${WORK_DIR}"
    local accp_jar; accp_jar="$(resolve_accp_jar)"
    echo "==> [full] ACCP jar: ${accp_jar}"

    local jtreg_home; jtreg_home="$(build_jtreg)"
    echo "==> [full] jtreg: ${jtreg_home}"

    local jdk_src; jdk_src="$(fetch_test_content)"
    local test_jdk="${jdk_src}/test/jdk"
    echo "==> [full] test content: ${test_jdk}"

    write_accp_security_props "${WORK_DIR}/accp.security" "${accp_jar}"
    local jtx="${WORK_DIR}/accp-exclusions.jtx"
    write_jtx "${jtx}"
    echo "==> [full] $(grep -cvE '^\s*$' "${jtx}" || true) test(s) excluded for JDK ${JDK_MAJOR}."

    # Resolve the test roots to absolute test/jdk-relative paths that exist.
    local run_paths=() r
    while IFS= read -r r; do
        if [[ -d "${test_jdk}/${r}" ]]; then
            run_paths+=("${r}")
        else
            echo "WARN: [full] configured root '${r}' not present at the pinned tag; skipping." >&2
        fi
    done < <(collect_test_roots)

    if [[ ${#run_paths[@]} -eq 0 ]]; then
        echo "ERROR: [full] no configured test roots exist in the checked-out tree." >&2
        exit 1
    fi

    local report="${WORK_DIR}/jtreg-report"
    local work="${WORK_DIR}/jtreg-work"
    rm -rf "${report}" "${work}"

    # ACCP on the bootclasspath so its classes resolve for every test JVM, plus
    # the security-properties override that installs it as provider #1.
    #
    # Use -vmoption (applies to every test JVM) for both. Do NOT also pass them
    # via -javaoption: jtreg's requires.VMProps collects VM options into a map
    # keyed by option, and the same -Xbootclasspath/a appearing on two channels
    # trips "Duplicate key vm.opt.x.Xbootclasspath/a" during @requires
    # evaluation, aborting the whole run.
    echo "==> [full] Running jtreg over ${#run_paths[@]} root(s)..."
    set +e
    "${jtreg_home}/bin/jtreg" \
        -jdk:"${TEST_JAVA_HOME}" \
        -exclude:"${jtx}" \
        -vmoption:-Xbootclasspath/a:"${accp_jar}" \
        -vmoption:-Djava.security.properties="${WORK_DIR}/accp.security" \
        -reportDir:"${report}" \
        -workDir:"${work}" \
        -automatic -ignore:quiet \
        -dir:"${test_jdk}" \
        "${run_paths[@]}"
    local jtreg_rc=$?
    set -e

    echo "==> [full] jtreg exit code: ${jtreg_rc}. Report: ${report}"
    # jtreg returns nonzero if any non-excluded test failed/errored. Surface that
    # unless the caller is enumerating failures to seed the exclusion lists.
    if [[ "${jtreg_rc}" -ne 0 && "${KEEP_GOING:-false}" != "true" ]]; then
        echo "ERROR: [full] unexpected (non-excluded) test failures. See ${report}." >&2
        exit "${jtreg_rc}"
    fi
    echo "==> [full] OK."
}

mkdir -p "${WORK_DIR}"
case "${MODE}" in
    smoke) run_smoke ;;
    full)  run_full ;;
esac
