// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/sha.h>
#define DIGEST_NAME       SHA256
#define DIGEST_BLOCK_SIZE 64
#include "hash_template.cpp.template"
