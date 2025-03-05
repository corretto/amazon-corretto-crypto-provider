// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef STRING_VECTOR_H
#define STRING_VECTOR_H

#include "compiler.h"

#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <string>
#include <vector>

namespace AmazonCorrettoCryptoProvider {

class ConcurrentStringVector {
private:
    std::vector<std::string> vec;
    mutable pthread_rwlock_t lock;

public:
    ConcurrentStringVector() { pthread_rwlock_init(&lock, nullptr); }

    ~ConcurrentStringVector() { pthread_rwlock_destroy(&lock); }

    // Disable copy constructors
    ConcurrentStringVector(const ConcurrentStringVector&);
    ConcurrentStringVector& operator=(const ConcurrentStringVector&);

    void push_back(const std::string& value)
    {
        pthread_rwlock_wrlock(&lock);
        vec.push_back(std::string(value));
        pthread_rwlock_unlock(&lock);
    }

    void clear()
    {
        pthread_rwlock_wrlock(&lock);
        vec.clear();
        pthread_rwlock_unlock(&lock);
    }

    size_t size() const
    {
        pthread_rwlock_rdlock(&lock);
        size_t vec_size = vec.size();
        pthread_rwlock_unlock(&lock);
        return vec_size;
    }

    std::vector<std::string> to_std() const
    {
        pthread_rwlock_rdlock(&lock);
        std::vector<std::string> out(vec); // Use copy constructor, no references
        pthread_rwlock_unlock(&lock);
        return out;
    }
};

} // namespace AmazonCorrettoCryptoProvider

#endif // STRING_VECTOR_H
