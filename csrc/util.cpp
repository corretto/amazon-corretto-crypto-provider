// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <stddef.h>
#include <string>
#include <sstream>
#include <openssl/err.h>
#include <cassert>
#include "generated-headers.h"

#include "util.h"
#include "env.h"

#define CLASSNOTFOUND_TYPE "java/lang/NoClassDefFoundError"

namespace AmazonCorrettoCryptoProvider {

unsigned long drainOpensslErrors() {
  unsigned long result = 0;
  unsigned long tmp = ERR_get_error();
  while (tmp != 0) {
    result = tmp;
    tmp = ERR_get_error();
  }
  return result;
}

std::string formatOpensslError(unsigned long errCode, const char *fallback) {
  if (errCode) {
    char buffer[256];
    ERR_error_string_n(errCode, buffer, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';
    return std::string(buffer);
  } else {
    return std::string(fallback);
  }
}
} // namespace
