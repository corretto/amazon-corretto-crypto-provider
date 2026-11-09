// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/digest.h>
#define DIGEST_NAME       sha3_256
#define JAVA_CLASS_NAME   SHA3256
#define DIGEST_LENGTH     32
#define DIGEST_BLOCK_SIZE 136
#include "hash_evp_template.cpp.template"
