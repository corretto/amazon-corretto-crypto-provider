// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Optional;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

public class TestResultLogger implements TestWatcher {
  /**
   * Reads the ACCP_TEST_COLOR environment variable and if it is case-insensitive equal to "false",
   * returns the empty string. Else, returns the proper control codes to set the color/font
   * specified by {@code code}.
   */
  private static final String maybeColor(String code) {
    final String envVarValue = System.getenv("ACCP_TEST_COLOR");
    if ("false".equalsIgnoreCase(envVarValue)) {
      return "";
    }

    return (char) 27 + "[" + code + "m";
  }

  private static final String BRIGHT_TEXT = maybeColor("1");
  private static final String BRIGHT_RED_TEXT = maybeColor("31;1");
  private static final String BRIGHT_CYAN_TEXT = maybeColor("36;1");
  private static final String NORMAL_TEXT = maybeColor("0");
  private static final String NOT_YET_FAILED_NOTICE = " ";
  private static final String ALREADY_FAILED_NOTICE = BRIGHT_RED_TEXT + "!" + NORMAL_TEXT;

  @SuppressWarnings("unused")
  private static final String STARTED_NOTICE = BRIGHT_TEXT + "[STARTED]         " + NORMAL_TEXT;

  private static final String ASSUMPTION_FAILED_NOTICE =
      BRIGHT_CYAN_TEXT + "[FALSE_ASSUMPTION]" + NORMAL_TEXT;
  private static final String FAILED_NOTICE = BRIGHT_RED_TEXT + "[FAILED]          " + NORMAL_TEXT;
  private static final String IGNORED_NOTICE =
      BRIGHT_CYAN_TEXT + "[IGNORED]         " + NORMAL_TEXT;

  private static volatile boolean alreadyFailed = false;

  @Override
  public void testDisabled(ExtensionContext context, Optional<String> reason) {
    printNotice(IGNORED_NOTICE, context, reason.orElse("Unspecified reason"));
  }

  @Override
  public void testSuccessful(ExtensionContext context) {
    // No-op
  }

  @Override
  public void testAborted(ExtensionContext context, Throwable cause) {
    printNotice(ASSUMPTION_FAILED_NOTICE, context, cause.toString());
  }

  @Override
  public void testFailed(ExtensionContext context, Throwable cause) {
    alreadyFailed = true;
    printNotice(FAILED_NOTICE, context, cause.getMessage(), cause);
  }

  private void printNotice(final String notice, ExtensionContext context) {
    printNotice(notice, context, "", null);
  }

  private void printNotice(final String notice, ExtensionContext context, String description) {
    printNotice(notice, context, description, null);
  }

  private void printNotice(
      final String notice, ExtensionContext context, String description, Throwable cause) {
    String methodName = context.getRequiredTestClass().getName();
    if (context.getTestMethod().isPresent()) {
      methodName += "." + context.getTestMethod().get().getName();
    }
    StringWriter causeText = new StringWriter();
    if (cause != null) {
      try (PrintWriter printWriter = new PrintWriter(causeText)) {
        printWriter.append(" @ ").append(String.valueOf(getFailureLocation(cause)));
        // Don't print out traces for Assert.* failures which throw subclasses of AssertionError.
        // Just for thrown exceptions
        if (AssertionError.class.equals(cause.getClass()) || !(cause instanceof AssertionError)) {
          causeText.append('\n');
          cause.printStackTrace(printWriter);
        }
      }
    }

    System.out.format(
        "%s%s %s: %s%s%n",
        alreadyFailed ? ALREADY_FAILED_NOTICE : NOT_YET_FAILED_NOTICE,
        notice,
        methodName,
        context.getDisplayName(),
        description,
        causeText);
  }

  public static StackTraceElement getFailureLocation(Throwable t) {
    final StackTraceElement[] stackTrace = t.getStackTrace();
    for (StackTraceElement e : stackTrace) {
      if (e.getClassName().startsWith("com.amazon.corretto.crypto.provider.")) {
        return e;
      }
    }
    if (stackTrace.length > 0) {
      return stackTrace[0];
    } else {
      return null;
    }
  }
}
