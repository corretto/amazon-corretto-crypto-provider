// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/md5.h>
#define DIGEST_NAME MD5
#define DIGEST_BLOCK_SIZE 64
#include "hash_template.cpp.template"
#include "hmac_template.cpp.template"
