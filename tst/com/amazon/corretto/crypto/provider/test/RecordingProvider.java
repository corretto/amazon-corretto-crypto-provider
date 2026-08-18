// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import java.security.Provider;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;

/**
 * A JCA {@link Provider} that registers no services of its own and records the service lookups that
 * reach it, then falls through (returns {@code null}) so the next provider in the list serves the
 * request. It is a passive "sniffer": insert one at a chosen position and it observes -- rather
 * than merely infers -- which lookups the JCA precedence scan routes through that position.
 *
 * <p>Because it serves nothing, it must be placed <em>immediately in front of</em> the real
 * provider it is meant to observe (e.g. {@code AccpRecorder -> ACCP}, {@code BcRecorder -> BC}): a
 * lookup that reaches the recorder is tallied and then satisfied by the real provider right behind
 * it. A lookup that an earlier provider already satisfied never reaches the recorder, which is
 * exactly what makes a downstream recorder a meaningful negative control.
 *
 * <p>Only lookups accepted by the record filter supplied at construction are tallied; every other
 * lookup passes through unrecorded so the counters stay meaningful.
 */
public final class RecordingProvider extends Provider {
  private static final long serialVersionUID = 1L;

  private final BiPredicate<String, String> recordFilter;
  private final ConcurrentHashMap<String, Integer> counters = new ConcurrentHashMap<>();

  /**
   * Records only the lookups for which {@code recordFilter} returns true.
   *
   * @param name this provider's JCA name; must be unique among the installed providers
   * @param recordFilter tallies a lookup only when it returns true for the (type, algorithm) pair
   */
  public RecordingProvider(final String name, final BiPredicate<String, String> recordFilter) {
    // Provider(String, double, String) is used deliberately: it is the only constructor available
    // under --release 8, which this package (com.amazon.corretto.crypto.provider.test) is compiled
    // against for JDK 8 targets. The Provider(String, String, String) overload is JDK 9+ only.
    super(name, 1.0d, "Records JCA service lookups that reach its position in the provider list");
    this.recordFilter = recordFilter;
  }

  @Override
  public synchronized Service getService(final String type, final String algorithm) {
    if (algorithm != null && recordFilter.test(type, algorithm)) {
      counters.merge(type + "/" + algorithm.toUpperCase(), 1, Integer::sum);
    }
    // Registers no services, so this returns null and the JCA scan falls through to the next
    // provider (the real one this recorder sits in front of).
    return super.getService(type, algorithm);
  }

  /**
   * Recorded lookups of service {@code type}, summed across all algorithms.
   *
   * <p>{@code type} is the JCA service-type <em>name</em> (e.g. {@code "KEM"}, {@code
   * "KeyPairGenerator"}), not a {@code Class}. That is deliberate: identifying services by their
   * JCA name string avoids a compile-time reference to JDK-version-specific SPI/type classes --
   * notably {@code javax.crypto.KEM} / {@code javax.crypto.KEMSpi}, which do not exist before JDK
   * 17's KEM backport. A caller that passed such a {@code .class} literal would fail to compile on
   * an older JDK; keying on the name string lets callers stay reflection-based and portable across
   * JDKs.
   */
  public int lookupsByType(final String type) {
    int total = 0;
    for (final Map.Entry<String, Integer> entry : counters.entrySet()) {
      if (entry.getKey().startsWith(type + "/")) {
        total += entry.getValue();
      }
    }
    return total;
  }

  /** Human-readable snapshot of the recorded counters, for assertion messages. */
  public String summary() {
    return counters.toString();
  }
}
