#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Uploads a Central Portal bundle zip (from the centralPortalBundle Gradle task) and polls until
# the Portal finishes validating it. Publishing itself stays manual: the upload always requests
# USER_MANAGED, so a human still reviews and clicks publish in the Portal UI.
#
# The token is a Sonatype Central Portal "user token" (not the account login), fetched from
# Secrets Manager. It behaves like base64(username:password) over Bearer auth.
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

response=$(curl --fail --silent --show-error --request POST \
  --header "Authorization: Bearer $token" \
  --form "bundle=@${bundle};type=application/octet-stream" \
  "https://central.sonatype.com/api/v1/publisher/upload?name=${name}&publishingType=USER_MANAGED")
deployment_id=$response
echo "Uploaded as deployment $deployment_id"

for _ in $(seq 1 30); do
  status=$(curl --fail --silent --show-error --request POST \
    --header "Authorization: Bearer $token" \
    "https://central.sonatype.com/api/v1/publisher/status?id=${deployment_id}")
  state=$(echo "$status" | python3 -c "import json,sys; print(json.load(sys.stdin)['deploymentState'])")
  echo "deploymentState=$state"
  case "$state" in
    VALIDATED) echo "$status"; exit 0 ;;
    FAILED) echo "::error::Portal validation failed"; echo "$status"; exit 1 ;;
    PENDING|VALIDATING) sleep 10 ;;
    *) echo "::error::Unexpected deploymentState $state"; echo "$status"; exit 1 ;;
  esac
done

echo "::error::Timed out waiting for validation"
exit 1
