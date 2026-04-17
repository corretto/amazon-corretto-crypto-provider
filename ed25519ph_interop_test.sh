#!/usr/bin/env bash
set -euo pipefail

ACCP_ROOT="$(cd "$(dirname "$0")" && pwd)"
ACCP_JAR="$ACCP_ROOT/build/lib/AmazonCorrettoCryptoProvider.jar"
NATIVE_LIB_DIR="$ACCP_ROOT/build/cmake"
OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
WORKDIR="$(mktemp -d)"

trap 'rm -rf "$WORKDIR"' EXIT

# Ed25519ph support via -pkeyopt instance:Ed25519ph requires OpenSSL >= 3.2.0
OPENSSL_VER=$($OPENSSL version | awk '{print $2}')
MIN_VER="3.2.0"
if printf '%s\n%s\n' "$MIN_VER" "$OPENSSL_VER" | sort -V | head -n1 | grep -qx "$MIN_VER"; then
    echo "OpenSSL version $OPENSSL_VER >= $MIN_VER, OK"
else
    echo "ERROR: OpenSSL >= $MIN_VER required for Ed25519ph (found $OPENSSL_VER)" >&2
    exit 1
fi

echo "=== Ed25519ph interop: ACCP (sign) -> Go & OpenSSL (verify) ==="
echo "workdir: $WORKDIR"

# ---------- Java signer ----------
cat > "$WORKDIR/Ed25519phSign.java" << 'JAVA_EOF'
import java.security.*;
import java.security.spec.*;
import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class Ed25519phSign {
    public static void main(String[] args) throws Exception {
        Provider accp = new AmazonCorrettoCryptoProvider();
        Security.addProvider(accp);

        // Generate an Ed25519 key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", accp);
        KeyPair kp = kpg.generateKeyPair();

        // Extract raw 32-byte public key from X.509 encoding
        // X.509 for Ed25519: 302a300506032b6570032100 || <32 bytes>
        byte[] x509 = kp.getPublic().getEncoded();
        byte[] rawPub = new byte[32];
        System.arraycopy(x509, x509.length - 32, rawPub, 0, 32);

        // The message to sign
        byte[] message = "hello from ACCP Ed25519ph".getBytes("UTF-8");

        // Sign with Ed25519ph (ACCP prehashes internally)
        Signature signer = Signature.getInstance("Ed25519ph", accp);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        // Output hex: pubkey, message, signature (one per line)
        System.out.println(hex(rawPub));
        System.out.println(hex(message));
        System.out.println(hex(signature));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }
}
JAVA_EOF

echo "--- Compiling Java signer ---"
javac -cp "$ACCP_JAR" "$WORKDIR/Ed25519phSign.java"

echo "--- Signing with ACCP Ed25519ph ---"
java -cp "$ACCP_JAR:$WORKDIR" \
     -Djava.library.path="$NATIVE_LIB_DIR" \
     Ed25519phSign > "$WORKDIR/sig_data.txt"

PUB_HEX=$(sed -n '1p' "$WORKDIR/sig_data.txt")
MSG_HEX=$(sed -n '2p' "$WORKDIR/sig_data.txt")
SIG_HEX=$(sed -n '3p' "$WORKDIR/sig_data.txt")

echo "  pubkey:    $PUB_HEX"
echo "  message:   $MSG_HEX"
echo "  signature: $SIG_HEX"

# ---------- Go verifier ----------
cat > "$WORKDIR/verify.go" << 'GO_EOF'
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <pubkey_hex> <message_hex> <signature_hex>\n", os.Args[0])
		os.Exit(2)
	}

	pubBytes, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad pubkey hex: %v\n", err)
		os.Exit(1)
	}
	msgBytes, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad message hex: %v\n", err)
		os.Exit(1)
	}
	sigBytes, err := hex.DecodeString(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad signature hex: %v\n", err)
		os.Exit(1)
	}

	pubKey := ed25519.PublicKey(pubBytes)

	// Ed25519ph: caller must pass the SHA-512 digest of the message
	digest := sha512.Sum512(msgBytes)

	err = ed25519.VerifyWithOptions(pubKey, digest[:], sigBytes, &ed25519.Options{
		Hash: crypto.SHA512,
	})
	if err != nil {
		fmt.Printf("FAIL: Ed25519ph signature verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("PASS: Ed25519ph signature verified successfully (ACCP -> Go)")
}
GO_EOF

echo "--- Verifying with Go Ed25519ph ---"
go run "$WORKDIR/verify.go" "$PUB_HEX" "$MSG_HEX" "$SIG_HEX"

# ---------- OpenSSL CLI verifier ----------
echo "--- Verifying with OpenSSL Ed25519ph ---"

# Build X.509 SPKI DER from raw 32-byte public key
# Ed25519 X.509 prefix: 302a300506032b6570032100
echo "302a300506032b6570032100${PUB_HEX}" | xxd -r -p > "$WORKDIR/pub.der"
$OPENSSL pkey -pubin -inform DER -in "$WORKDIR/pub.der" -out "$WORKDIR/pub.pem"

# Write raw message and signature bytes
echo -n "$MSG_HEX" | xxd -r -p > "$WORKDIR/msg.bin"
echo -n "$SIG_HEX" | xxd -r -p > "$WORKDIR/sig.bin"

# Verify: -rawin means OpenSSL receives the raw message (not pre-digested),
# and -pkeyopt instance:Ed25519ph selects the prehash variant.
$OPENSSL pkeyutl -verify -pubin -inkey "$WORKDIR/pub.pem" -rawin \
    -pkeyopt instance:Ed25519ph \
    -in "$WORKDIR/msg.bin" -sigfile "$WORKDIR/sig.bin"

echo "PASS: Ed25519ph signature verified successfully (ACCP -> OpenSSL)"
