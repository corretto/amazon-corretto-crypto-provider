// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/sha.h>
#define DIGEST_NAME SHA384
// SHA384 uses the SHA-512 context type
#define CTX               SHA512_CTX
#define DIGEST_BLOCK_SIZE 128
#include "hash_template.cpp.template"
