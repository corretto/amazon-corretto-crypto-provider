#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Signs the release jars in DIR: a JCE (jarsigner) signature on each platform jar, matching
# fakePublish, and a detached GPG signature on every jar. Verifies both before exiting.
#
#   test     throwaway keys generated here; the jars are NOT releasable
#   release  production keys from the ACCP release account (CodeBuild runner role only)
#
# Secrets stay in shell variables and pipes. The only secret material written to disk is the
# keystore (jarsigner needs a file) and the GPG home directory, both under a private temp dir that is
# shredded on exit.
#
# Usage: sign.sh test|release DIR
set -euo pipefail

mode=$1
dir=$2

work=$(mktemp -d)
chmod 700 "$work"
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
keystore="$work/keystore.jks"

cleanup() {
  gpgconf --kill gpg-agent 2>/dev/null || true
  if command -v shred >/dev/null; then
    find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# Feeds the GPG passphrase on fd 3 through a pipe; here-strings can be backed by temp files.
gpg_with_passphrase() {
  gpg --batch --pinentry-mode loopback --passphrase-fd 3 "$@" 3< <(printf '%s' "$gpg_passphrase")
}

load_test_keys() {
  KEYSTORE_PASSWORD=$(openssl rand -hex 32)
  echo "::add-mask::$KEYSTORE_PASSWORD"
  export KEYSTORE_PASSWORD
  jce_alias=accp-test
  jce_signer="CN=ACCP test signing"
  gpg_uid=accp-test@invalid
  gpg_passphrase=''

  # JKS matches the format of the production keystore.
  keytool -genkeypair -alias "$jce_alias" -keyalg RSA -keysize 3072 -validity 1 \
    -dname "$jce_signer" -storetype JKS -keystore "$keystore" \
    -storepass:env KEYSTORE_PASSWORD -keypass:env KEYSTORE_PASSWORD 2>/dev/null
  gpg_with_passphrase --quick-gen-key "ACCP test signing <$gpg_uid>" rsa3072 sign 1d 2>/dev/null
}

# Same material as the Staging buildspec in AccpPublicReleaseCDK
# (fetchSecretsCommands / SIGNING_SECRETS_CONFIG).
load_release_keys() {
  local bucket=s3://838297025124.us-west-2.provider-signing-material
  secret_field() {
    aws secretsmanager get-secret-value --secret-id "$1" --query SecretString --output text \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['$2'], end='')"
  }

  KEYSTORE_PASSWORD=$(secret_field provider-signing-kestore-password-2024 password)
  echo "::add-mask::$KEYSTORE_PASSWORD"
  export KEYSTORE_PASSWORD
  gpg_passphrase=$(secret_field gpg-signing password)
  echo "::add-mask::$gpg_passphrase"
  gpg_uid=$(secret_field gpg-signing keyId)
  jce_signer="CN=Amazon Web Services, OU=Java Software Code Signing, O=Oracle Corporation"

  jce_alias=$(aws s3 cp "$bucket/accp_gradle_2024.properties" - | sed -n 's/^jcecertAlias=//p' | tr -d '\r')
  [[ -n "$jce_alias" ]] || { echo "::error::jcecertAlias not found in accp_gradle_2024.properties"; exit 1; }

  aws s3 cp --quiet "$bucket/accp_signing_key_full_2024.jks" "$keystore"

  # mvn_gpg.tgz is a gpg 2.1+ home directory. Its secret keys are in private-keys-v1.d, which
  # gpg --import cannot read, so extract only the keyrings as GNUPGHOME (no revocation certs).
  aws s3 cp "$bucket/mvn_gpg.tgz" - \
    | tar -xzf - -C "$GNUPGHOME" --strip-components=1 --wildcards \
        '*/pubring.kbx' '*/private-keys-v1.d/*'
  # The archive predates the key's expiry extension; the committed public key carries it.
  # signing-key.asc is committed rather than fetched to avoid a keyserver dependency. To refresh
  # it after the expiry is extended again, with GNUPGHOME pointing at a scratch directory:
  #   curl -s 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x5EFEEFE6BD0BD916' | gpg --import
  #   gpg --armor --export-options export-minimal \
  #     --export 53935F41B347016137A25EDB5EFEEFE6BD0BD916 > signing-key.asc
  # and check the fingerprint and new expiry before committing.
  gpg --batch --import "$(dirname "$0")/signing-key.asc" 2>/dev/null
  # Field 15 is '+' only when the secret is present (not a stub); field 2 'e'/'r' is expired/revoked.
  gpg --batch --with-colons --list-secret-keys "$gpg_uid" \
    | awk -F: '$1 == "sec" && $15 == "+" && $2 !~ /[er]/ { ok = 1 } END { exit !ok }' \
    || { echo "::error::GPG secret key $gpg_uid missing, stubbed, or expired"; exit 1; }
}

case "$mode" in
  test) load_test_keys ;;
  release) load_release_keys ;;
  *) echo "usage: $0 test|release DIR" >&2; exit 2 ;;
esac

gpg --batch --armor --export "$gpg_uid" > "$dir/signing-key.pub"

for jar in "$dir"/*-linux-*.jar; do
  jarsigner -keystore "$keystore" -storepass:env KEYSTORE_PASSWORD \
    -tsa http://timestamp.digicert.com "$jar" "$jce_alias" >/dev/null
  verify=$(jarsigner -verify -verbose -certs "$jar")
  grep -q "jar verified" <<<"$verify"
  grep -qF "Signed by \"$jce_signer\"" <<<"$verify"
  echo "$jar: JCE signature verified"
done

for jar in "$dir"/*.jar; do
  gpg_with_passphrase --armor --local-user "$gpg_uid" --detach-sign "$jar"
  gpg --batch --verify "$jar.asc" "$jar" 2>/dev/null
  echo "$jar: GPG signature verified"
done
