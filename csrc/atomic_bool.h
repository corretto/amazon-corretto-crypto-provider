// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ATOMIC_BOOL_H
#define ATOMIC_BOOL_H

#include "compiler.h"

#ifdef HAVE_CPP11
#include <atomic>
#else
// For pre-C++11, we use pthread_mutex to sync access to the AtomicBool
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#endif

namespace AmazonCorrettoCryptoProvider {

#ifdef HAVE_CPP11

using AtomicBool = std::atomic<bool>;

#else

// If lock/unlock failes, we still proceed
// Since we are using the default value when initializing the mutex, these failures should not happen.
class UniquePthreadMutexLock {
public:
    UniquePthreadMutexLock(pthread_mutex_t* mutex)
        : mutex_(mutex)
    {
        int status = pthread_mutex_lock(mutex_);
        if (status != 0) {
            fprintf(stderr, "pthread_mutex_lock failed with error %d", status);
        }
    }

    ~UniquePthreadMutexLock()
    {
        int status = pthread_mutex_unlock(mutex_);
        if (status != 0) {
            fprintf(stderr, "pthread_mutex_unlock failed with error %d", status);
        }
    }

private:
    pthread_mutex_t* mutex_;
};

class AtomicBool {
public:
    AtomicBool(bool initial_value)
        : value_(initial_value)
    {
        int status = pthread_mutex_init(&value_mutex_, nullptr);
        if (status != 0) {
            // let's exit if we can't even initalize a mutex :(
            fprintf(stderr, "failed to initialize the mutex; pthread_mutex_init failed with error code %d", status);
            exit(EXIT_FAILURE);
        }
    }

    ~AtomicBool() { pthread_mutex_destroy(&value_mutex_); }

    bool load()
    {
        UniquePthreadMutexLock lock(&value_mutex_);
        return value_;
    }

    void store(bool value)
    {
        UniquePthreadMutexLock lock(&value_mutex_);
        value_ = value;
    }

private:
    bool value_;
    pthread_mutex_t value_mutex_; // used to sync access to value_

    // Disabling default constructors
    AtomicBool();
    AtomicBool(AtomicBool const&);
    AtomicBool& operator=(AtomicBool const&);
};

#endif

} // namespace AmazonCorrettoCryptoProvider

#endif // ATOMIC_BOOL_H
