// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.keygeneratorspi;
/**
 * For each type of secret key, we need to implement this interface and pass an instance of
 * it to SecretKeyGenerator to get a service (SPI) class.
 */
public interface SecretKeyProperties {
    String getName(); // the name of the algorithm, like AES
    int defaultKeySize(); // the default key size, in bits, to be used in case a key size is not provided
    void checkKeySizeIsValid(int keySize); // throws an exception if the given algorithm does not support keys of "keySize"
}
