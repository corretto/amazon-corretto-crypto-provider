// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef TEST_FAKE_JNI_H
#define TEST_FAKE_JNI_H 1

#include "test_utils.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <jni.h>
#include <memory>
#include <string>
#include <vector>

// A fake JNIEnv for native tests that borrow Java byte arrays.
struct FakeArray : _jbyteArray {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> copy;
    uint8_t empty_byte = 0x42;
    bool copied;
    bool fail = false;
    bool cleansed = false;
    jint release_mode = -1;

    explicit FakeArray(size_t len, bool copied = false)
        : bytes(len, 0x42)
        , copied(copied)
    {
    }
};

struct FakeJni : JNIEnv {
    JNINativeInterface_ table = JNINativeInterface_();
    std::vector<std::unique_ptr<FakeArray> > arrays;
    std::vector<jarray> releases;
    std::vector<jarray> commits;
    std::vector<jarray> acquired;
    int active = 0;
    int acquisitions = 0;
    int new_arrays = 0;
    int reads = 0;
    int writes = 0;
    bool fail_new = false;
    _jclass exception_class;
    std::string exception_name;
    bool exception_pending = false;

    FakeJni()
    {
        functions = &table;
        releases.reserve(8);
        commits.reserve(8);
        acquired.reserve(8);
        table.IsSameObject = [](JNIEnv* env, jobject first, jobject second) -> jboolean {
            TEST_ASSERT(state(env).active == 0);
            return first == second ? JNI_TRUE : JNI_FALSE;
        };
        table.GetArrayLength = [](JNIEnv* env, jarray array) -> jsize {
            TEST_ASSERT(state(env).active == 0);
            return static_cast<jsize>(static_cast<FakeArray*>(array)->bytes.size());
        };
        table.NewByteArray = [](JNIEnv* env, jsize len) -> jbyteArray {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            ++jni.new_arrays;
            if (jni.fail_new) {
                return nullptr;
            }
            jni.arrays.emplace_back(new FakeArray(static_cast<size_t>(len)));
            std::fill(jni.arrays.back()->bytes.begin(), jni.arrays.back()->bytes.end(), 0);
            return jni.arrays.back().get();
        };
        table.GetByteArrayRegion = [](JNIEnv* env, jbyteArray array, jsize off, jsize len, jbyte* dst) {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            ++jni.reads;
            memcpy(dst, static_cast<FakeArray*>(array)->bytes.data() + off, static_cast<size_t>(len));
        };
        table.SetByteArrayRegion = [](JNIEnv* env, jbyteArray array, jsize off, jsize len, const jbyte* src) {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            ++jni.writes;
            jni.commits.push_back(array);
            memcpy(static_cast<FakeArray*>(array)->bytes.data() + off, src, static_cast<size_t>(len));
        };
        table.ExceptionCheck = [](JNIEnv* env) -> jboolean {
            TEST_ASSERT(state(env).active == 0);
            return state(env).exception_pending ? JNI_TRUE : JNI_FALSE;
        };
        table.FindClass = [](JNIEnv* env, const char* name) -> jclass {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            jni.exception_name = name;
            return &jni.exception_class;
        };
        table.ThrowNew = [](JNIEnv* env, jclass clazz, const char*) -> jint {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0 && clazz == &jni.exception_class);
            jni.exception_pending = true;
            return 0;
        };
        table.GetPrimitiveArrayCritical = [](JNIEnv* env, jarray array, jboolean* copied) -> void* {
            FakeJni& jni = state(env);
            FakeArray& a = *static_cast<FakeArray*>(array);
            ++jni.acquisitions;
            jni.acquired.push_back(array);
            if (a.fail) {
                return nullptr;
            }
            ++jni.active;
            *copied = a.copied ? JNI_TRUE : JNI_FALSE;
            if (a.bytes.empty()) {
                return &a.empty_byte;
            }
            if (a.copied) {
                a.copy = a.bytes;
                return a.copy.data();
            }
            return a.bytes.data();
        };
        table.ReleasePrimitiveArrayCritical = [](JNIEnv* env, jarray array, void* ptr, jint mode) {
            FakeJni& jni = state(env);
            FakeArray& a = *static_cast<FakeArray*>(array);
            TEST_ASSERT(jni.active > 0);
            TEST_ASSERT(ptr == (a.bytes.empty() ? &a.empty_byte : (a.copied ? a.copy.data() : a.bytes.data())));
            --jni.active;
            jni.releases.push_back(array);
            a.release_mode = mode;
            if (a.copied) {
                a.cleansed = std::all_of(a.copy.begin(), a.copy.end(), [](uint8_t b) { return b == 0; });
                if (mode == 0) {
                    a.bytes = a.copy;
                }
                a.copy.clear();
            }
        };
    }

    static FakeJni& state(JNIEnv* env) { return *static_cast<FakeJni*>(env); }
};

#endif // TEST_FAKE_JNI_H
