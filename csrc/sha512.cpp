// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/sha.h>
#define DIGEST_NAME SHA512
#define DIGEST_BLOCK_SIZE 128
#include "hash_template.cpp.template"
#include "hmac_template.cpp.template"
