// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef RSA_H
#define RSA_H 1

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "util.h"
#include "bn.h"

namespace AmazonCorrettoCryptoProvider {

class RSA_auto {
private:
    RSA *rsa;

    RSA_auto(void *no_init) {
        rsa = NULL;
    }

    RSA_auto(const RSA_auto &) DELETE_IMPLICIT;
    RSA_auto &operator=(const RSA_auto &) DELETE_IMPLICIT;
public:
    RSA_auto(RSA *ptr) {
        rsa = ptr;
    }

    RSA_auto() {
        rsa = RSA_new();
        if (!rsa) {
            throw_openssl(EX_OOM, "Failed to allocate new RSA object");
        }
    }

    ~RSA_auto() {
        // RSA_free internally takes care of checking for which parts of the RSA structure
        // are initialized and freeing them appropriately.
        RSA_free(rsa);
    }

    void set(RSA *ptr) {
      RSA_free(rsa);
      rsa = ptr;
    }

    RSA *take() {
        RSA *pRsa = rsa;
        rsa = NULL;

        return pRsa;
    }

    RSA *operator->() {
        return *this;
    }

    operator RSA *() {
        if (!rsa) {
            abort();
        }

        return rsa;
    }
};

} // namespace AmazonCorrettoCryptoProvider

#endif // RSA_H
