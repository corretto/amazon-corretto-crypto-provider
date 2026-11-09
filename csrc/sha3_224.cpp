// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/digest.h>
#define DIGEST_NAME       sha3_224
#define JAVA_CLASS_NAME   SHA3224
#define DIGEST_LENGTH     28
#define DIGEST_BLOCK_SIZE 144
#include "hash_evp_template.cpp.template"
