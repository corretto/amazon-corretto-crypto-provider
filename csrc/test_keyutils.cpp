// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "keyutils.h"
#include "test_utils.h"
#include "util.h"


using namespace AmazonCorrettoCryptoProvider;

namespace {

#define DER_LENGTH 138
/*
SEQUENCE (3 elem)
  INTEGER 0
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
  OCTET STRING (1 elem)
    SEQUENCE (3 elem)
      INTEGER 1
      OCTET STRING (32 byte) 4309C0677521479DA8FA16DF15736134686FE38E479195AB794A7214CBE2494F
      [1] (1 elem)
        BIT STRING (520 bit) 0000010011011110000010010000100000000111000000110010111010001111001101…
 */
static const uint8_t validPKCS8ECKey[DER_LENGTH] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0x43, 0x09, 0xc0, 0x67, 0x75, 0x21, 0x47, 0x9d, 0xa8, 0xfa, 0x16, 0xdf,
    0x15, 0x73, 0x61, 0x34, 0x68, 0x6f, 0xe3, 0x8e, 0x47, 0x91, 0x95, 0xab,
    0x79, 0x4a, 0x72, 0x14, 0xcb, 0xe2, 0x49, 0x4f, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xde, 0x09, 0x08, 0x07, 0x03, 0x2e, 0x8f, 0x37, 0x9a, 0xd5,
    0xad, 0xe5, 0xc6, 0x9d, 0xd4, 0x63, 0xc7, 0x4a, 0xe7, 0x20, 0xcb, 0x90,
    0xa0, 0x1f, 0x18, 0x18, 0x72, 0xb5, 0x21, 0x88, 0x38, 0xc0, 0xdb, 0xba,
    0xf6, 0x99, 0xd8, 0xa5, 0x3b, 0x83, 0xe9, 0xe3, 0xd5, 0x61, 0x99, 0x73,
    0x42, 0xc6, 0x6c, 0xe8, 0x0a, 0x95, 0x40, 0x41, 0x3b, 0x0d, 0x10, 0xa7,
    0x4a, 0x93, 0xdb, 0x5a, 0xe7, 0xec,
};

void test_deserialize_valid_key() {
    EVP_PKEY* result = der2EvpPrivateKey(validPKCS8ECKey, DER_LENGTH, false, EX_INVALID_KEY);
    TEST_ASSERT(result);
    EVP_PKEY_free(result);
}

void test_deserialize_invalid_der() {
    uint8_t invalidKey[DER_LENGTH];
    memcpy(invalidKey, validPKCS8ECKey, DER_LENGTH);

    // This makes the private key invalid
    invalidKey[34] = 0;
    try {
        der2EvpPrivateKey(invalidKey, DER_LENGTH, false, EX_INVALID_KEY);
        FAIL();
    } catch (...) {
        // Expected
    }
}

void test_deserialize_empty() {
    // This makes the DER encoding invalid for a PKCS8 key but still the right length
    uint8_t emptyKey[1] = {0x00};
    try {
        der2EvpPrivateKey(emptyKey, 0, false, EX_INVALID_KEY);
        FAIL();
    } catch (...) {
        // Expected
    }
}

void test_deserialize_extra_data() {
    uint8_t invalidKey[DER_LENGTH];
    memcpy(invalidKey, validPKCS8ECKey, DER_LENGTH);

    // This sets the der to have 0 elements but still has data and will hit the extra key info
    invalidKey[0] = 0;
    try {
        der2EvpPrivateKey(invalidKey, DER_LENGTH, false, EX_INVALID_KEY);
        FAIL();
    } catch (...) {
        // Expected
    }
}

}// anon namespace

int main() {
    BEGIN_TEST();
    RUNTEST(test_deserialize_valid_key);
    RUNTEST(test_deserialize_invalid_der);
    RUNTEST(test_deserialize_empty);
    RUNTEST(test_deserialize_extra_data);
    END_TEST();
}
