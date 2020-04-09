// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <openssl/err.h>

int foo() {
    // make sure we pull in some of libcrypto at least
    ERR_print_errors_fp(stderr);
    return 0;
}
