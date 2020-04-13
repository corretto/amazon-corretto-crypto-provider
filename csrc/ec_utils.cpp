// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "bn.h"

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    buildCurve
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_buildGroup
  (JNIEnv *pEnv, jclass, jint nid)
{
    EC_GROUP* group;
    try {
        raii_env env(pEnv);

        if (unlikely(!(group = EC_GROUP_new_by_curve_name(nid)))) {
            throw_openssl("Unable to get group");
        }

        return (jlong) group;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    freeCurve
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_freeGroup
  (JNIEnv *, jclass, jlong group)
{
    EC_GROUP_free((EC_GROUP*) group);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    curveNameToInfo
 * Signature: (Ljava/lang/String;[B[B[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_curveNameToInfo(
  JNIEnv *pEnv,
  jclass,
  jstring curveName,
  jintArray mArr,
  jbyteArray pArr,
  jbyteArray aArr,
  jbyteArray bArr,
  jbyteArray cofactorArr,
  jbyteArray gxArr,
  jbyteArray gyArr,
  jbyteArray orderArr)
{
    try {
        raii_env env(pEnv);

        if (!curveName) {
            throw_java_ex(EX_NPE, "Curve name must not be null");
        }
        jni_string jniCurve(env, curveName);

        int nid = OBJ_txt2nid(jniCurve.native_str);
        if (nid == NID_undef) {
            ERR_clear_error();
            return 0;
        }

        EC_GROUP_auto group(nid);
        if (unlikely(!group.group)) {
            unsigned long errCode = drainOpensslErrors();
            if (errCode == ERR_PACK(ERR_LIB_EC, EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP)) {
                throw_java_ex(EX_ILLEGAL_ARGUMENT, "Unknown curve");
            } else {
                throw_java_ex(EX_RUNTIME_CRYPTO,
                    formatOpensslError(errCode, "Unable to create group"));
            }
        }

        BigNumObj pBN;
        BigNumObj aBN;
        BigNumObj bBN;
        BigNumObj cfBN;
        BigNumObj gxBN;
        BigNumObj gyBN;
        BigNumObj orderBN;

        const EC_POINT* generator = NULL;
        const EC_METHOD * method = NULL;
        int fieldNid = 0;
        int m = 0;

        // Figure out which type of group this is
        method = EC_GROUP_method_of(group);
        if (!method) {
            throw_openssl("Unable to acquire method");
        }
        fieldNid = EC_METHOD_get_field_type(method);

        if (EC_GROUP_get_cofactor(group, cfBN, NULL) != 1) {
            throw_openssl("Unable to get cofactor");
        }
        cfBN.toJavaArray(env, cofactorArr);

        generator = EC_GROUP_get0_generator(group);
        if (!generator) {
            throw_openssl("Unable to get generator");
        }

        switch (fieldNid) {
            case NID_X9_62_prime_field:
                if (EC_GROUP_get_curve_GFp(group, pBN, aBN, bBN, NULL) != 1) {
                    throw_openssl("Unable to get group information");
                }
                if (EC_POINT_get_affine_coordinates_GFp(group, generator, gxBN, gyBN, NULL) != 1) {
                    throw_openssl("Unable to get generator coordinates");
                }
                break;
            case NID_X9_62_characteristic_two_field:
                if (EC_GROUP_get_curve_GF2m(group, pBN, aBN, bBN, NULL) != 1) {
                    throw_openssl("Unable to get group information");
                }
                if (EC_POINT_get_affine_coordinates_GF2m(group, generator, gxBN, gyBN, NULL) != 1) {
                    throw_openssl("Unable to get generator coordinates");
                }
                m = EC_GROUP_get_degree(group);
                env->SetIntArrayRegion(mArr, 0, 1, &m);
                env.rethrow_java_exception();
                break;
        }

        gxBN.toJavaArray(env, gxArr);
        gyBN.toJavaArray(env, gyArr);

        pBN.toJavaArray(env, pArr);
        aBN.toJavaArray(env, aArr);
        bBN.toJavaArray(env, bArr);


        if (EC_GROUP_get_order(group, orderBN, NULL) != 1) {
            throw_openssl("Unable to get group order");
        }
        orderBN.toJavaArray(env, orderArr);

        return nid;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}
