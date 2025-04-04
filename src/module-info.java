// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

module com.amazon.corretto.crypto.provider {
  requires java.logging;

  exports com.amazon.corretto.crypto.provider;
  exports com.amazon.corretto.crypto.utils;

  provides java.security.Provider with
      com.amazon.corretto.crypto.provider.ServiceProviderFactory;
}
