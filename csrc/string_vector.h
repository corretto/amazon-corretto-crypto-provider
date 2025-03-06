// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef STRING_VECTOR_H
#define STRING_VECTOR_H

#include "compiler.h"

#include <cstdio>
#include <cstdlib>
#include <deque>
#include <pthread.h>
#include <string>

namespace AmazonCorrettoCryptoProvider {

class ConcurrentStringVector {
private:
    std::deque<std::string> vec;
    const size_t limit;
    mutable pthread_rwlock_t lock;

public:
    ConcurrentStringVector(size_t limit)
        : limit(limit)
    {
        pthread_rwlock_init(&lock, nullptr);
    }

    ~ConcurrentStringVector() { pthread_rwlock_destroy(&lock); }

    // Disable copy constructors
    ConcurrentStringVector(const ConcurrentStringVector&);
    ConcurrentStringVector& operator=(const ConcurrentStringVector&);

    void push_back(const std::string& value)
    {
        pthread_rwlock_wrlock(&lock);
        if (vec.size() >= limit) { // If we're at the limit, pop FIFO
            vec.pop_front();
        }
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
        std::vector<std::string> out(vec.begin(), vec.end()); // Use copy constructor, no references
        pthread_rwlock_unlock(&lock);
        return out;
    }
};

} // namespace AmazonCorrettoCryptoProvider

#endif // STRING_VECTOR_H
