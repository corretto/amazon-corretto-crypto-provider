// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.FipsStatusException;
import javax.crypto.KeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
// NOTE: we need to take global r/w lock on TestUtil because FIPS self test breakages
//       are global and would affect other tests executed concurrently with this one.
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class FipsStatusTest {

  private final AmazonCorrettoCryptoProvider provider = AmazonCorrettoCryptoProvider.INSTANCE;

  @Test
  public void givenAccpBuiltWithFips_whenAWS_LC_fips_failure_callback_expectException()
      throws Exception {
    if (provider.isFips()) {
      assertTrue(provider.isFipsStatusOk());
      assertNotNull(KeyGenerator.getInstance("AES", provider));
      // call the failure callback
      NativeTestHooks.callAwsLcFipsFailureCallback();
      assertFalse(provider.isFipsStatusOk());
      // we should not be able to get any service object
      assertThrows(FipsStatusException.class, () -> KeyGenerator.getInstance("AES", provider));
      // we need to flip the status back to OK so the rest of tests would work. In practice, once
      // the flag is set to false, it remains false.
      NativeTestHooks.resetFipsStatus();
    }
  }
}
