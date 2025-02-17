// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ATOMIC_BOOL_H
#define ATOMIC_BOOL_H

#include "compiler.h"

#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <pthread.h>
#include <string>
#include <vector>

namespace AmazonCorrettoCryptoProvider {

class ConcurrentStringVector {
private:
    std::vector<std::string> vec;
    mutable std::mutex mutex;

public:
    void push_back(const std::string& value)
    {
        std::unique_lock<std::mutex> lock(mutex);
        vec.push_back(std::string(value));
    }

    void clear()
    {
        std::unique_lock<std::mutex> lock(mutex);
        vec.clear();
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(mutex);
        return vec.size();
    }

    // TODO [childw] note about how implementing full iterator interface would be more
    // efficient, but this is sufficient for rarely-checked self-test failure functionality
    void copy(std::vector<std::string>& out) const
    {
        out.clear();
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& s : vec) {
            out.push_back(std::string(s));
        }
    }
};

} // namespace AmazonCorrettoCryptoProvider

#endif // ATOMIC_BOOL_H
