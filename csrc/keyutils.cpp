// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "keyutils.h"
#include "auto_free.h"
#include "bn.h"
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
// EVP_PKEY_keygen_deterministic (seed -> ML-KEM key) lives in this experimental header. Every AWS-LC
// flavor ACCP builds against declares it with the same signature, so the seed decode below is compiled
// unconditionally rather than only for regular FIPS: one parser for all flavors cannot drift per build,
// and the grammar it accepts stays a single thing to reason about.
// TODO [AWS-LC-FIPS 4.x]: drop this experimental include once the FIPS module can d2i seed-format ML-KEM keys.
#include <openssl/experimental/kem_deterministic_api.h>
#include <openssl/obj.h>
#include <openssl/pkcs8.h>
#include <openssl/rsa.h>

namespace AmazonCorrettoCryptoProvider {

// Parses a PKCS8 ML-KEM private key via the raw APIs (bypassing the ASN.1 method absent from
// AWS-LC-FIPS 3.1.0). Returns nullptr for inputs it does not handle; the key-construction helpers it
// delegates to may queue an OpenSSL error when they reject a well-formed but invalid key.
// der2EvpPrivateKey calls this as a fallover after d2i_PrivateKey fails. Defined below, next to
// parseMLKEMPublicKey.
// TODO [AWS-LC-FIPS 4.x]: drop this fallover parser once the FIPS module implements priv_decode for ML-KEM.
static EVP_PKEY* parseMLKEMPrivateKey(const unsigned char* der, const int derLen);

EVP_PKEY* der2EvpPrivateKey(const unsigned char* der,
    const int derLen,
    const int evpType,
    bool shouldCheckPrivate,
    const char* javaExceptionClass)
{
    const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer

    // Scope away the errors a failed d2i_PrivateKey queues. Its failure is expected for ML-KEM in
    // regular FIPS (see the fallover below), and when nothing can parse |der| the errors are still
    // in the queue for throw_openssl to report before this guard unwinds.
    ErrorQueueMark error_mark;

    // Try the standard decoder first so non-ML-KEM keys (and, in non-FIPS builds, ML-KEM keys) incur
    // no ML-KEM parsing overhead.
    EVP_PKEY* result = d2i_PrivateKey(evpType, NULL, &der_mutable_ptr, derLen);

    // Fallover for ML-KEM PKCS8: AWS-LC-FIPS 3.1.0 has no priv_decode for ML-KEM, so d2i_PrivateKey
    // fails on every ML-KEM private key there. Only when the caller asked for a KEM key and
    // d2i_PrivateKey produced nothing do we hand-roll the parse via the raw APIs. Each CHOICE
    // reconstructs the key exactly the way AWS-LC's decoder does (identically in v1.72.0 and v5.0.0),
    // so the two agree per CHOICE:
    //   - expandedKey sets only the raw secret key (KEM_KEY_set_raw_secret_key), leaving the public key
    //     unpopulated, so getPublicKey().getEncoded() fails for such a key in every build;
    //   - seed derives the whole key pair from the seed, public key included.
    // parseMLKEMPrivateKey returns nullptr for inputs it cannot handle, which in a non-FIPS build is
    // everything: it accepts nothing d2i_PrivateKey has not already accepted there.
    // TODO [AWS-LC-FIPS 4.x]: drop this raw-key decode path once the FIPS module supports d2i_PrivateKey for ML-KEM.
    if (result == nullptr && evpType == EVP_PKEY_KEM) {
        EVP_PKEY* mlkem = parseMLKEMPrivateKey(der, derLen);
        if (mlkem != nullptr) {
            if (shouldCheckPrivate && !checkKey(mlkem)) {
                EVP_PKEY_free(mlkem);
                throw_openssl(javaExceptionClass, "Key fails check");
            }
            return mlkem;
        }
    }

    if (!result) {
        throw_openssl(javaExceptionClass, "Unable to convert PKCS8_PRIV_KEY_INFO to EVP_PKEY");
    }

    // Only meaningful once a key came back: d2i_PrivateKey leaves |der_mutable_ptr| untouched when it
    // fails, so checking it first reported every decode failure as "Extra key information".
    if (der + derLen != der_mutable_ptr) {
        EVP_PKEY_free(result);
        throw_openssl(javaExceptionClass, "Extra key information");
    }

    if (isRsaKeyType(EVP_PKEY_base_id(result))) {
        const RSA* rsa = EVP_PKEY_get0_RSA(result);

        if (rsa) {
            // We need strip zero CRT values which can confuse OpenSSL
            const BIGNUM* n;
            const BIGNUM* e;
            const BIGNUM* d;
            const BIGNUM* p;
            const BIGNUM* q;
            const BIGNUM* dmp1;
            const BIGNUM* dmq1;
            const BIGNUM* iqmp;
            bool need_rebuild = false;

            RSA_get0_key(rsa, &n, &e, &d);
            RSA_get0_factors(rsa, &p, &q);
            RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
            // If blinding is set and any of the parameters required for blinding
            // are NULL, rebuild to turn blinding off. Otherwise, rebuild if any
            // of the params are 0-valued to NULL them out.
            if ((RSA_test_flags(rsa, RSA_FLAG_NO_BLINDING) == 0) && (!e || !p || !q)) {
                need_rebuild = true;
            } else if (e && BN_is_zero(e)) {
                need_rebuild = true;
            } else if (p && BN_is_zero(p)) {
                need_rebuild = true;
            } else if (q && BN_is_zero(q)) {
                need_rebuild = true;
            } else if (dmp1 && BN_is_zero(dmp1)) {
                need_rebuild = true;
            } else if (dmq1 && BN_is_zero(dmq1)) {
                need_rebuild = true;
            } else if (iqmp && BN_is_zero(iqmp)) {
                need_rebuild = true;
            }

            if (need_rebuild) {
                // This key likely only has (n, d) set. Very weird, but it happens in java sometimes.
                RSA_auto nulled_rsa;
                // No need to copy n or d since new_private_RSA_key_with_no_e does not take ownership.
                nulled_rsa.set(new_private_RSA_key_with_no_e(n, d));
                if (e != nullptr && !BN_is_zero(e)) {
                    // Need to copy e since RSA_set0_key takes ownership.
                    BigNumObj e_copy = BigNumObj::fromBIGNUM(e);
                    if (!RSA_set0_key(nulled_rsa, nullptr, e_copy, nullptr)) {
                        throw_openssl("Unable to set e for RSA");
                    }
                    e_copy.releaseOwnership();
                }
                EVP_PKEY_set1_RSA(result, nulled_rsa);
                shouldCheckPrivate = false; // We cannot check private keys without CRT parameters
            }
        }
    }

    if (shouldCheckPrivate && !checkKey(result)) {
        EVP_PKEY_free(result);
        throw_openssl(javaExceptionClass, "Key fails check");
    }

    return result;
}

// ML-KEM public-key SubjectPublicKeyInfo (SPKI) encode/decode.
//
// AWS-LC-FIPS 3.1.0 does not implement i2d_PUBKEY / d2i_PUBKEY for ML-KEM (the ML-KEM
// EVP_PKEY_ASN1_METHOD has no pub_encode/pub_decode in the FIPS module), so those calls raise
// UNSUPPORTED_ALGORITHM. We hand-roll the X.509 SubjectPublicKeyInfo from the raw public key so
// ML-KEM key serialization works in regular FIPS. The SubjectPublicKeyInfo format is specified in
// RFC 9935 Section 4 (Subject Public Key Fields), with the formal ASN.1 module in Appendix A:
// https://datatracker.ietf.org/doc/html/rfc9935#section-4
// https://datatracker.ietf.org/doc/html/rfc9935#appendix-A
// ML-KEM SPKI is fully determined by (OID, rawPublicKey), so this is byte-identical to what
// i2d_PUBKEY produces in non-FIPS builds.
// TODO [AWS-LC-FIPS 4.x]: drop this hand-rolled SPKI path once the FIPS module implements i2d/d2i_PUBKEY for ML-KEM.

// True when |nid| identifies one of the three ML-KEM parameter sets.
static bool isMLKEMNid(int nid) { return nid == NID_MLKEM512 || nid == NID_MLKEM768 || nid == NID_MLKEM1024; }

// Maps an ML-KEM raw public-key length (FIPS 203, Table 3) to its NID, or NID_undef.
//
// NOTE: this mapping is only unambiguous for ML-KEM keys. AWS-LC registers legacy Kyber-R3 under the
// same EVP_PKEY_KEM type (see KEM_find_kem_by_nid), and Kyber-512/768/1024-R3 have byte-for-byte the
// same public- and secret-key lengths as ML-KEM-512/768/1024, so a length alone cannot tell the two
// families apart. Callers must therefore only reach this helper for keys the library itself could not
// encode: Java_..._EvpKey_encodePublicKey tries i2d_PUBKEY first, and encodeExpandedMLKEMPrivateKey is
// only reached after EVP_marshal_private_key fails. Both of those only fail for EVP_PKEY_KEM in
// regular FIPS, where AWS-LC-FIPS 3.1.0 supplies no pub_encode/pub_decode/priv_encode/priv_decode at
// all -- so the only ML-KEM codecs in play are the ones in this file, which key off the OID and reject
// every non-ML-KEM OID, and ACCP itself never generates anything but ML-KEM.
static int mlkemNidForPublicKeyLen(size_t raw_len)
{
    switch (raw_len) {
    case 800:
        return NID_MLKEM512;
    case 1184:
        return NID_MLKEM768;
    case 1568:
        return NID_MLKEM1024;
    default:
        return NID_undef;
    }
}

size_t encodeMLKEMPublicKey(const EVP_PKEY* key, uint8_t** out)
{
    CHECK_OPENSSL(key);
    CHECK_OPENSSL(EVP_PKEY_id(key) == EVP_PKEY_KEM);
    CHECK_OPENSSL(out);
    size_t raw_len = 0;
    CHECK_OPENSSL(EVP_PKEY_get_raw_public_key(key, nullptr, &raw_len));
    int nid = mlkemNidForPublicKeyLen(raw_len);
    if (nid == NID_undef) {
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "Invalid ML-KEM public key size");
    }
    OPENSSL_buffer_auto raw_pub(raw_len);
    // OPENSSL_buffer_auto does not check its own allocation, and the next call memcpy's into it.
    CHECK_OPENSSL(raw_pub.buf != nullptr);
    CHECK_OPENSSL(EVP_PKEY_get_raw_public_key(key, raw_pub, &raw_len));
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE { OID }, subjectPublicKey BIT STRING }.
    // The ML-KEM AlgorithmIdentifier carries no parameters; the BIT STRING is the raw public key.
    // See RFC 9935 Section 4 (Subject Public Key Fields):
    // https://datatracker.ietf.org/doc/html/rfc9935#section-4
    CBB cbb, spki, algorithm, pub;
    CHECK_OPENSSL(CBB_init(&cbb, 0));
    // spotless:off
    if (!CBB_add_asn1(&cbb, &spki, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&algorithm, nid) ||
        !CBB_add_asn1(&spki, &pub, CBS_ASN1_BITSTRING) ||
        !CBB_add_u8(&pub, 0) /* unused bits */ ||
        !CBB_add_bytes(&pub, raw_pub, raw_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error serializing ML-KEM public key");
    }
    // spotless:on
    size_t out_len;
    // A failed CBB_finish leaves the CBB owning its buffer and does not write |*out|, so clean the CBB
    // up and leave |*out| alone. A successful CBB_finish transfers the buffer to |*out| and cleans up.
    if (!CBB_finish(&cbb, out, &out_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error finalizing ML-KEM public key");
    }
    return out_len;
}

// Parses an ML-KEM X.509 SubjectPublicKeyInfo into an EVP_PKEY via its raw public key. Returns
// nullptr when |der| is not an ML-KEM SPKI, or when the raw public key is the wrong length for the
// OID's parameter set (in which case EVP_PKEY_kem_new_raw_public_key queues an error).
// der2EvpPublicKey calls this as a fallover after d2i_PUBKEY fails.
static EVP_PKEY* parseMLKEMPublicKey(const unsigned char* der, const int derLen)
{
    CBS cbs, spki, algorithm, oid, bit_string;
    CBS_init(&cbs, der, derLen);
    // spotless:off
    if (!CBS_get_asn1(&cbs, &spki, CBS_ASN1_SEQUENCE) || CBS_len(&cbs) != 0 ||
        !CBS_get_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&algorithm, &oid, CBS_ASN1_OBJECT)) {
        return nullptr;
    }
    // spotless:on
    int nid = OBJ_cbs2nid(&oid);
    if (!isMLKEMNid(nid)) {
        return nullptr;
    }
    // The ML-KEM AlgorithmIdentifier has no parameters; the subjectPublicKey BIT STRING follows.
    uint8_t unused_bits = 0;
    // spotless:off
    if (CBS_len(&algorithm) != 0 ||
        !CBS_get_asn1(&spki, &bit_string, CBS_ASN1_BITSTRING) || CBS_len(&spki) != 0 ||
        !CBS_get_u8(&bit_string, &unused_bits) || unused_bits != 0) {
        return nullptr;
    }
    // spotless:on
    return EVP_PKEY_kem_new_raw_public_key(nid, CBS_data(&bit_string), CBS_len(&bit_string));
}

// Every ML-KEM parameter set uses the same 64-byte keygen seed, d || z (FIPS 203, Algorithm 16).
static const size_t MLKEM_SEED_LEN = 64;

// Expands a raw ML-KEM keygen seed (d || z) into a full EVP_PKEY (public key included) via
// deterministic keygen, the same way AWS-LC's KEM_KEY_set_raw_keypair_from_seed does. Returns nullptr
// on failure, which makes the caller's parse fail and surfaces out of der2EvpPrivateKey as a decode
// failure. Only regular FIPS reaches this, because AWS-LC-FIPS 3.1.0's ASN.1 method cannot decode a
// seed-format key and every other flavor decodes it inside d2i_PrivateKey.
// TODO [AWS-LC-FIPS 4.x]: drop this seed-expansion helper once the FIPS module can d2i seed-format ML-KEM keys.
static EVP_PKEY* mlkemKeyFromSeed(int nid, const uint8_t* seed, size_t seed_len)
{
    // AWS-LC's kem_priv_decode length-checks the seed against the parameter set's keygen_seed_len
    // before expanding it, so check it here too rather than relying on the experimental keygen API's
    // internal validation.
    if (seed_len != MLKEM_SEED_LEN) {
        return nullptr;
    }
    EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, nullptr));
    if (!ctx.isInitialized() || EVP_PKEY_CTX_kem_set_params(ctx, nid) != 1 || EVP_PKEY_keygen_init(ctx) != 1) {
        return nullptr;
    }
    EVP_PKEY* pkey = nullptr;
    size_t len = seed_len;
    if (!EVP_PKEY_keygen_deterministic(ctx, &pkey, seed, &len)) {
        return nullptr;
    }
    return pkey;
}

// Hand-rolled PKCS8 private-key path for ML-KEM. The tag constants and skipOptionalField below exist
// only to serve parseMLKEMPrivateKey, so all three are deleted together, along with the seed branch
// and mlkemKeyFromSeed above it.
// TODO [AWS-LC-FIPS 4.x]: drop this hand-rolled PKCS8 path once the FIPS module implements priv_decode for ML-KEM.

// Tags of the two optional PrivateKeyInfo / OneAsymmetricKey trailing fields, spelled exactly as
// AWS-LC v5.0.0's EVP_parse_private_key spells them (kAttributesTag and kPublicKeyTag in
// evp_asn1.c): attributes is recognized only in its constructed form and publicKey only in its
// primitive form. That asymmetry is what DER requires of each, not an inconsistency: attributes is
// a SET, which is always constructed, while publicKey is an IMPLICIT-tagged BIT STRING, which is
// primitive. Deliberately not lenient about the other form of either tag -- see
// parseMLKEMPrivateKey.
static const unsigned MLKEM_PKCS8_ATTRIBUTES_TAG = CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0;
static const unsigned MLKEM_PKCS8_PUBLIC_KEY_TAG = CBS_ASN1_CONTEXT_SPECIFIC | 1;

// Skips the optional field tagged |tag| from |cbs| if present. Returns false only when the tag is
// present but its element is malformed; a missing field is not an error.
static bool skipOptionalField(CBS* cbs, unsigned tag)
{
    if (!CBS_peek_asn1_tag(cbs, tag)) {
        return true;
    }
    return CBS_get_asn1(cbs, nullptr, tag) == 1;
}

// See forward declaration above der2EvpPrivateKey. Parses a PKCS8 ML-KEM private key via the raw
// APIs, bypassing the ASN.1 method that AWS-LC-FIPS 3.1.0 lacks. The private-key CHOICEs are
// specified in RFC 9935 Section 6 (Private Key Format), with the formal ASN.1 module in Appendix A:
// https://datatracker.ietf.org/doc/html/rfc9935#section-6
// https://datatracker.ietf.org/doc/html/rfc9935#appendix-A
//
// This is a stand-in for AWS-LC's decoder, not an improvement on it: it deliberately mirrors
// EVP_parse_private_key (crypto/evp_extra/evp_asn1.c) plus kem_priv_decode
// (crypto/evp_extra/p_kem_asn1.c) accept-for-accept and reject-for-reject, so that deleting this
// function once AWS-LC-FIPS decodes ML-KEM natively is a behavioral no-op. Two consequences worth
// spelling out, both matching AWS-LC:
//   - the "both" CHOICE (SEQUENCE { seed, expandedKey }) is rejected, even though it is well-formed
//     RFC 9935 and is what BouncyCastle's ML-KEM getEncoded() emits by default. AWS-LC has not
//     implemented it in any flavor ("Case 3 ... not implemented yet"), so accepting it here would
//     make ACCP quietly lose the ability on the FIPS bump;
//   - trailing bytes after the CHOICE inside the privateKey OCTET STRING are ignored rather than
//     rejected, because kem_priv_decode does not check CBS_len(key) after extracting the CHOICE.
//
// The version mirrored is AWS-LC v5.0.0, the decoder this function is destined to be replaced by,
// and NOT the v1.72.0 that build.gradle pins for non-FIPS and experimental-FIPS builds. v1.72.0's
// EVP_parse_private_key is laxer about the two optional trailing fields: it spells kAttributesTag
// without CBS_ASN1_CONSTRUCTED, consumes the attributes field from the wrong CBS, and never checks
// for trailing data inside the PrivateKeyInfo SEQUENCE, so it silently ignores encodings this parser
// rejects (a constructed [1] where a primitive [1] publicKey belongs, for instance). Mirroring where
// ACCP is going rather than where it is pinned is the point; do not relax these checks to match
// v1.72.0.
//
// The resulting divergence is bounded and one-directional: everything this function accepts,
// v1.72.0 accepts too, so it is strictly the stricter of the two and the fallover can never widen
// what a non-FIPS build accepts. It only ever shows up as regular FIPS rejecting a malformed
// encoding that the other builds ignore, and it disappears once the pinned mainline tag reaches
// v5.x. The one intended behavioral difference between the builds is serialization, not parsing:
// see the seed CHOICE below.
//
// AWS-LC-FIPS 3.1.0 has no ML-KEM ASN.1 method at all, so in regular FIPS this function is the
// entire decoder. Returns nullptr for non-ML-KEM inputs. der2EvpPrivateKey calls this as a fallover
// after d2i_PrivateKey fails, so in non-FIPS / experimental-FIPS builds only inputs AWS-LC itself
// rejected reach it, and it rejects those too.
static EVP_PKEY* parseMLKEMPrivateKey(const unsigned char* der, const int derLen)
{
    CBS cbs, pkcs8, algorithm, oid, priv;
    uint64_t version = 0;
    CBS_init(&cbs, der, derLen);
    // The outer structure is a PrivateKeyInfo (RFC 5208, version 0) or a OneAsymmetricKey (RFC 5958,
    // version 1). Accept both versions, matching EVP_parse_private_key, so this regular-FIPS fallover
    // parses everything the non-FIPS d2i_PrivateKey path parses. Rejecting version 1 here would make
    // ACCP refuse OneAsymmetricKey encodings that other providers (and ACCP's own non-FIPS builds)
    // emit and accept.
    // spotless:off
    if (!CBS_get_asn1(&cbs, &pkcs8, CBS_ASN1_SEQUENCE) || CBS_len(&cbs) != 0 ||
        !CBS_get_asn1_uint64(&pkcs8, &version) || version > 1 ||
        !CBS_get_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&algorithm, &oid, CBS_ASN1_OBJECT)) {
        return nullptr;
    }
    // spotless:on
    int nid = OBJ_cbs2nid(&oid);
    if (!isMLKEMNid(nid)) {
        return nullptr;
    }
    // The ML-KEM AlgorithmIdentifier has no parameters. The PrivateKey OCTET STRING wraps one of the
    // CHOICE alternatives, dispatched on its tag below.
    // spotless:off
    if (CBS_len(&algorithm) != 0 ||
        !CBS_get_asn1(&pkcs8, &priv, CBS_ASN1_OCTETSTRING)) {
        return nullptr;
    }
    // spotless:on
    // attributes [0] Attributes OPTIONAL. Ignored, exactly as EVP_parse_private_key ignores it.
    if (!skipOptionalField(&pkcs8, MLKEM_PKCS8_ATTRIBUTES_TAG)) {
        return nullptr;
    }
    // publicKey [1] BIT STRING OPTIONAL, permitted only in a version-1 OneAsymmetricKey. Ignored: the
    // expanded CHOICE reconstructs ML-KEM keys from the secret key alone in AWS-LC too, so honoring the
    // public key here would make the two disagree.
    if (CBS_peek_asn1_tag(&pkcs8, MLKEM_PKCS8_PUBLIC_KEY_TAG)
        && (version != 1 || !skipOptionalField(&pkcs8, MLKEM_PKCS8_PUBLIC_KEY_TAG))) {
        return nullptr;
    }
    // Trailing data within the SEQUENCE, rejected as mainline EVP_parse_private_key rejects it.
    if (CBS_len(&pkcs8) != 0) {
        return nullptr;
    }
    if (CBS_peek_asn1_tag(&priv, CBS_ASN1_CONTEXT_SPECIFIC | 0)) {
        // seed CHOICE ([0] IMPLICIT OCTET STRING, the raw d || z keygen seed). AWS-LC-FIPS 3.1.0 cannot
        // d2i a seed-format ML-KEM key, so expand the seed into a full key. The seed itself is then
        // dropped, and this is the one intended FIPS-vs-non-FIPS behavioral difference in ML-KEM key
        // handling: mainline AWS-LC's KEM_KEY carries a seed field (v1.72.0 included) and re-emits the
        // seed CHOICE from it, while AWS-LC-FIPS 3.1.0's KEM_KEY has no such field, so nothing can hold
        // the seed and getEncoded() emits the expanded CHOICE in regular FIPS. Parsing is unaffected --
        // both CHOICEs are accepted in every build. Documented in README.md under "Notable differences
        // between ACCP and ACCP-FIPS".
        // TODO [AWS-LC-FIPS 4.x]: drop this seed branch once the FIPS module can d2i seed-format ML-KEM keys.
        CBS seed;
        if (!CBS_get_asn1(&priv, &seed, CBS_ASN1_CONTEXT_SPECIFIC | 0)) {
            return nullptr;
        }
        return mlkemKeyFromSeed(nid, CBS_data(&seed), CBS_len(&seed));
    }
    if (CBS_peek_asn1_tag(&priv, CBS_ASN1_OCTETSTRING)) {
        // expandedKey CHOICE. EVP_PKEY_kem_new_raw_secret_key validates the length against the parameter
        // set's secret_key_len and returns NULL otherwise (surfaced by der2EvpPrivateKey as a decode
        // failure), which is the same check kem_priv_decode makes before KEM_KEY_set_raw_secret_key.
        CBS expanded;
        if (!CBS_get_asn1(&priv, &expanded, CBS_ASN1_OCTETSTRING)) {
            return nullptr;
        }
        return EVP_PKEY_kem_new_raw_secret_key(nid, CBS_data(&expanded), CBS_len(&expanded));
    }
    // Any other tag, the "both" CHOICE included. See the note above about staying reject-for-reject
    // with kem_priv_decode.
    return nullptr;
}

EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass)
{
    // Scope away the errors a failed d2i_PUBKEY queues. Its failure is expected for ML-KEM in regular
    // FIPS (see the fallover below), and when nothing can parse |der| the errors are still in the queue
    // for throw_openssl to report before this guard unwinds.
    ErrorQueueMark error_mark;

    // Try the standard decoder first so non-ML-KEM keys (and, in non-FIPS builds, ML-KEM keys) incur
    // no ML-KEM parsing overhead.
    const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer
    EVP_PKEY* result = d2i_PUBKEY(NULL, &der_mutable_ptr, derLen);
    if (result != nullptr) {
        if (der + derLen != der_mutable_ptr) {
            EVP_PKEY_free(result);
            throw_openssl(javaExceptionClass, "Extra key information");
        }
        if (!checkKey(result)) {
            EVP_PKEY_free(result);
            throw_openssl(javaExceptionClass, "Key fails check");
        }
        return result;
    }

    // d2i_PUBKEY could not parse |der|. In regular FIPS, AWS-LC-FIPS 3.1.0 has no pub_decode for
    // ML-KEM, so d2i_PUBKEY raises UNSUPPORTED_ALGORITHM on ML-KEM SPKI; fall over to the hand-rolled
    // parser. parseMLKEMPublicKey returns nullptr for non-ML-KEM inputs, so a genuinely unparseable
    // key still throws below.
    // TODO [AWS-LC-FIPS 4.x]: drop this ML-KEM SPKI fallover once the FIPS module supports d2i_PUBKEY for ML-KEM.
    EVP_PKEY* mlkem = parseMLKEMPublicKey(der, derLen);
    if (mlkem == nullptr) {
        throw_openssl(javaExceptionClass, "Unable to parse key");
    }
    if (!checkKey(mlkem)) {
        EVP_PKEY_free(mlkem);
        throw_openssl(javaExceptionClass, "Key fails check");
    }
    return mlkem;
}

bool checkKey(const EVP_PKEY* key)
{
    int keyType = EVP_PKEY_base_id(key);
    bool result = false;

    const RSA* rsaKey;
    const BIGNUM* p;
    const BIGNUM* q;
    const EC_KEY* ecKey;

    switch (keyType) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        rsaKey = EVP_PKEY_get0_RSA(key);
        RSA_get0_factors(rsaKey, &p, &q);
        // RSA_check_key only works when sufficient private values are set
        if (p && !BN_is_zero(p) && q && !BN_is_zero(q)) {
            result = RSA_check_key(rsaKey) == 1;
        } else {
            // We don't have enough information to actually check the key
            result = true;
        }

        break;
    case EVP_PKEY_EC:
        ecKey = EVP_PKEY_get0_EC_KEY(key);
        result = EC_KEY_check_key(ecKey) == 1;

        break;
    default:
        // Keys we can't check, we just claim are fine, because there is nothing else we can do.
        result = true;
    }
    return result;
}

const EVP_MD* digestFromJstring(raii_env& env, jstring digestName)
{
    if (!digestName) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Null Digest name");
        return NULL;
    }
    jni_string name(env, digestName);
    const EVP_MD* result = EVP_get_digestbyname(name.native_str);

    if (!result) {
        throw_openssl("Unable to get digest");
    }

    return result;
}

RSA* new_private_RSA_key_with_no_e(BIGNUM const* n, BIGNUM const* d)
{
    RSA* result = ::RSA_new_private_key_no_e(n, d);

    if (result == nullptr) {
        throw_openssl("RSA_new_private_key_no_e failed.");
    }

    return result;
}

#if !defined(FIPS_BUILD) || defined(EXPERIMENTAL_FIPS_BUILD)
size_t encodeExpandedMLDSAPrivateKey(const EVP_PKEY* key, uint8_t** out)
{
    CHECK_OPENSSL(key);
    CHECK_OPENSSL(EVP_PKEY_id(key) == EVP_PKEY_PQDSA);
    CHECK_OPENSSL(out);
    size_t raw_len;
    int nid = NID_undef;
    // See Section 4, Table 2 of https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
    switch (EVP_PKEY_size(key)) { // switch on signature size for |key|'s algorithm
    case 2420:
        nid = NID_MLDSA44;
        raw_len = 2560;
        break;
    case 3309:
        nid = NID_MLDSA65;
        raw_len = 4032;
        break;
    case 4627:
        nid = NID_MLDSA87;
        raw_len = 4896;
        break;
    default:
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "Invalid ML-DSA signature size");
    }
    OPENSSL_buffer_auto raw_expanded(raw_len);
    // OPENSSL_buffer_auto does not check its own allocation, and the next call memcpy's into it.
    CHECK_OPENSSL(raw_expanded.buf != nullptr);
    CHECK_OPENSSL(EVP_PKEY_get_raw_private_key(key, raw_expanded, &raw_len));
    CBB cbb, pkcs8, algorithm, priv, expanded;
    CHECK_OPENSSL(CBB_init(&cbb, 0));
    // Encoding below is based on expandedKey CHOICE member of PrivateKey ASN.1 structures in:
    // https://github.com/lamps-wg/dilithium-certificates/blob/main/X509-ML-DSA-2025.asn
    // spotless:off
    if (!CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&algorithm, nid) ||
        !CBB_add_asn1(&pkcs8, &priv, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_asn1(&priv, &expanded, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&expanded, raw_expanded, raw_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error serializing expanded ML-DSA key");
    }
    // spotless:on
    size_t out_len;
    // A failed CBB_finish leaves the CBB owning its buffer and does not write |*out|, so clean the CBB
    // up and leave |*out| alone. A successful CBB_finish transfers the buffer to |*out| and cleans up.
    if (!CBB_finish(&cbb, out, &out_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error finalizing expanded ML-DSA key");
    }
    return out_len;
}
#endif // !defined(FIPS_BUILD) || defined(EXPERIMENTAL_FIPS_BUILD)

// ML-KEM expanded-format private-key PKCS8 encode. Unguarded (unlike the ML-DSA variant above):
// regular FIPS relies on this because AWS-LC-FIPS 3.1.0 cannot marshal ML-KEM private keys (the
// ML-KEM EVP_PKEY_ASN1_METHOD has no priv_encode in the FIPS module) and lacks seed support. The
// raw-key APIs it uses (EVP_PKEY_get_raw_private_key, OBJ_nid2cbb) are available in the FIPS module.
// TODO [AWS-LC-FIPS 4.x]: drop this hand-rolled encode once the FIPS module supports priv_encode for ML-KEM.
size_t encodeExpandedMLKEMPrivateKey(const EVP_PKEY* key, uint8_t** out)
{
    CHECK_OPENSSL(key);
    CHECK_OPENSSL(EVP_PKEY_id(key) == EVP_PKEY_KEM);
    CHECK_OPENSSL(out);
    size_t raw_len = 0;
    CHECK_OPENSSL(EVP_PKEY_get_raw_private_key(key, nullptr, &raw_len));
    int nid = NID_undef;
    // See FIPS 203, Table 3: secret_key_len per parameter set. As with mlkemNidForPublicKeyLen above,
    // these lengths are shared with legacy Kyber-R3, so this switch is only sound because the caller
    // reaches it exclusively after EVP_marshal_private_key has failed -- which for EVP_PKEY_KEM only
    // happens in regular FIPS, where no non-ML-KEM KEM key can exist.
    switch (raw_len) {
    case 1632:
        nid = NID_MLKEM512;
        break;
    case 2400:
        nid = NID_MLKEM768;
        break;
    case 3168:
        nid = NID_MLKEM1024;
        break;
    default:
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "Invalid ML-KEM secret key size");
    }
    OPENSSL_buffer_auto raw_expanded(raw_len);
    // OPENSSL_buffer_auto does not check its own allocation, and the next call memcpy's into it.
    CHECK_OPENSSL(raw_expanded.buf != nullptr);
    CHECK_OPENSSL(EVP_PKEY_get_raw_private_key(key, raw_expanded, &raw_len));
    CBB cbb, pkcs8, algorithm, priv, expanded;
    CHECK_OPENSSL(CBB_init(&cbb, 0));
    // Encoding below is based on the expandedKey CHOICE member of the PrivateKey structure in
    // RFC 9935 Section 6 (Private Key Format), with the formal ASN.1 module in Appendix A:
    // https://datatracker.ietf.org/doc/html/rfc9935#section-6
    // https://datatracker.ietf.org/doc/html/rfc9935#appendix-A
    // spotless:off
    if (!CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&algorithm, nid) ||
        !CBB_add_asn1(&pkcs8, &priv, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_asn1(&priv, &expanded, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&expanded, raw_expanded, raw_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error serializing expanded ML-KEM key");
    }
    // spotless:on
    size_t out_len;
    // A failed CBB_finish leaves the CBB owning its buffer and does not write |*out|, so clean the CBB
    // up and leave |*out| alone. A successful CBB_finish transfers the buffer to |*out| and cleans up.
    if (!CBB_finish(&cbb, out, &out_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error finalizing expanded ML-KEM key");
    }
    return out_len;
}

size_t encodeRfc5915EcPrivateKey(const EVP_PKEY* key, uint8_t** out)
{
    CHECK_OPENSSL(key);
    CHECK_OPENSSL(EVP_PKEY_id(key) == EVP_PKEY_EC);
    CHECK_OPENSSL(out);
    int nid = EVP_PKEY_id(key);
    if (nid == NID_undef) {
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "Unknown EC key type");
    }
    const ASN1_OBJECT* oid_obj = OBJ_nid2obj(nid);
    if (oid_obj == nullptr) {
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "No EC key OID for NID");
    }
    const uint8_t* oid_data = OBJ_get0_data(oid_obj);
    if (oid_data == nullptr) {
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "No DER representation for OBJ");
    }
    int oid_data_len = OBJ_length(oid_obj);
    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key);
    CBB cbb, pkcs8, algorithm, oid, priv;
    CHECK_OPENSSL(CBB_init(&cbb, 0));
    // spotless:off
    if (!CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&oid, oid_data, oid_data_len) ||
        !EC_KEY_marshal_curve_name(&algorithm, EC_KEY_get0_group(ec_key)) ||
        !CBB_add_asn1(&pkcs8, &priv, CBS_ASN1_OCTETSTRING) ||
        // Set |enc_flags| to 0 below to force encoding of redundant curve OID
        // in the inner private key encoding.
        !EC_KEY_marshal_private_key(&priv, ec_key, 0 /* enc_flags */) ||
        !CBB_flush(&cbb)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error serializing expanded EC key");
    }
    // spotless:on
    size_t out_len;
    // A failed CBB_finish leaves the CBB owning its buffer and does not write |*out|, so clean the CBB
    // up and leave |*out| alone. A successful CBB_finish transfers the buffer to |*out| and cleans up.
    if (!CBB_finish(&cbb, out, &out_len)) {
        CBB_cleanup(&cbb);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error finalizing expanded EC key");
    }
    return out_len;
}

}
