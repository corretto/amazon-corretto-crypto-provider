// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/digest.h>
#define DIGEST_NAME       sha3_512
#define JAVA_CLASS_NAME   SHA3512
#define DIGEST_LENGTH     64
#define DIGEST_BLOCK_SIZE 72
#include "hash_evp_template.cpp.template"
