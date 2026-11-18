#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Uploads a Central Portal bundle zip (from portal_bundle.py) and polls until
# the Portal finishes validating it. Publishing itself stays manual: the upload always requests
# USER_MANAGED, so a human still reviews and clicks publish in the Portal UI.
#
# The token is a Sonatype Central Portal "user token" (not the account login), fetched from
# Secrets Manager. It behaves like base64(username:password) over Bearer auth.
#
# If STAGED_JARS_DIR is set, the platform jars are downloaded back from the VALIDATED deployment into
# it, and each must match the bundle byte for byte. The staged-test jobs then test the exact staged
# files. Only this job holds the token, so it does the download for them.
#
# Usage: publish.sh BUNDLE_ZIP [DEPLOYMENT_NAME]
set -euo pipefail

bundle=$1
name=${2:-$(basename "$bundle" .zip)}

token_secret_id=maven-accp-release

token=$(aws secretsmanager get-secret-value --secret-id "$token_secret_id" --query SecretString --output text \
  | python3 -c "
import base64, json, sys
secret = json.load(sys.stdin)
print(base64.b64encode(f\"{secret['username']}:{secret['password']}\".encode()).decode(), end='')
")
echo "::add-mask::$token"

# Feeds the Authorization header to curl as a config on stdin, keeping the token out of curl's argv
# (and so out of the process table). printf is a bash builtin, so it never spawns with the token.
portal_curl() {
  printf 'header = "Authorization: Bearer %s"\n' "$token" \
    | curl --config - --fail --silent --show-error "$@"
}

fetch_staged_jars() {
  mkdir -p "$STAGED_JARS_DIR"
  local path out expected actual
  for path in $(python3 -c "import sys, zipfile; print('\n'.join(zipfile.ZipFile(sys.argv[1]).namelist()))" "$bundle" \
      | grep -E -- '-(linux|osx)-[a-z0-9_]+\.jar$'); do
    out="$STAGED_JARS_DIR/$(basename "$path")"
    portal_curl --output "$out" \
      "https://central.sonatype.com/api/v1/publisher/deployment/${deployment_id}/download/${path}"
    expected=$(python3 -c "import hashlib, sys, zipfile; print(hashlib.sha256(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2])).hexdigest())" "$bundle" "$path")
    actual=$(sha256sum "$out" | cut -d' ' -f1)
    if [ "$expected" != "$actual" ]; then
      echo "::error::$path from staging does not match the bundle ($actual != $expected)"
      exit 1
    fi
    echo "Fetched $path from staging, sha256 $actual"
  done
}

response=$(portal_curl --request POST \
  --form "bundle=@${bundle};type=application/octet-stream" \
  "https://central.sonatype.com/api/v1/publisher/upload?name=${name}&publishingType=USER_MANAGED")
deployment_id=$response
echo "Uploaded as deployment $deployment_id"

for _ in $(seq 1 30); do
  # The deployment already exists, so a transient status error must not abort: rerunning would
  # upload a duplicate deployment.
  if ! status=$(portal_curl --request POST "https://central.sonatype.com/api/v1/publisher/status?id=${deployment_id}"); then
    echo "::warning::Status request failed, retrying"
    sleep 10
    continue
  fi
  state=$(echo "$status" | python3 -c "import json,sys; print(json.load(sys.stdin)['deploymentState'])")
  echo "deploymentState=$state"
  case "$state" in
    VALIDATED)
      echo "$status"
      if [ -n "${STAGED_JARS_DIR:-}" ]; then fetch_staged_jars; fi
      exit 0
      ;;
    FAILED) echo "::error::Portal validation failed"; echo "$status"; exit 1 ;;
    PENDING|VALIDATING) sleep 10 ;;
    *) echo "::error::Unexpected deploymentState $state"; echo "$status"; exit 1 ;;
  esac
done

echo "::error::Timed out waiting for validation"
exit 1
