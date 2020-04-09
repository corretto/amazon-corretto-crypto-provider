// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a single test-case for Known Answer Tests encoded in RSP files.
 *
 */
public class RspTestEntry {
  private static final Pattern NAMELESS_HEADER_ENTRY = Pattern.compile("\\[([^=]+)\\]");
  private static final Pattern HEADER_ENTRY = Pattern.compile("\\[(\\S+)\\s*=\\s*(\\S+)\\]");
  private static final Pattern INSTANCE_ENTRY = Pattern.compile("(\\S+)\\s*=\\s*(\\S+)");

  private final Map<String, String> header_;
  private final Map<String, String> instance_;

  private RspTestEntry(final Map<String, String> header, final Map<String, String> instance) {
    header_ = header;
    instance_ = instance;
  }

  /**
   * Returns information about the current section of tests being executed. This information is
   * generally constant across numerous sequential tests.
   */
  public Map<String, String> getHeader() {
    return header_;
  }

  /**
   * Returns a specific entry from the header.
   *
   * @see {@link #getHeader()}
   */
  public String getHeader(final String field) {
    return getHeader().get(field);
  }

  /**
   * Returns information regarding this specific test case.
   */
  public Map<String, String> getInstance() {
    return instance_;
  }

  /**
   * Returns a specific entry from this specific test case.
   *
   * @see {@link #getInstance()}
   */
  public String getInstance(final String field) {
    return getInstance().get(field);
  }

  /**
   * Returns a specific entry from this test case after interpreting it as hex-encoded binary.
   *
   * @see {@link #getInstance(String)}
   */
  public byte[] getInstanceFromHex(final String field) {
    return TestUtil.decodeHex(getInstance(field));
  }

  public ByteBuffer getInstanceBufferFromHex(final String field) {
    final byte[] array = getInstanceFromHex(field);
    final ByteBuffer buffer = ByteBuffer.allocateDirect(array.length);
    buffer.put(array);
    buffer.flip();
    return buffer;
  }

  @Override
  public String toString() {
    return "RspTestEntry [header=" + header_ + ", instance=" + instance_ + "]";
  }

  /**
   * Parses data provided by {@code in} as a standard CAVP/CAVS file of test vectors and returns an
   * iterator over the test cases.
   * <ul>
   * <li>Lines with comments are proceeded by #
   * <li>Blocks of data are separated by blank lines
   * <li>Headers for each section consist of Key/Value pairs of the format: {@code [KEY=VALUE]}
   * <li>Test cases within each section consist of Key/Value pairs of the format: {@code KEY=VALUE}
   * </ul>
   * 
   * @see <a href="http://csrc.nist.gov/groups/STM/cavp/">NIST - CRYPTOGRAPHIC ALGORITHM VALIDATION
   *      PROGRAM (CAVP)</a>
   */
  public static Iterator<RspTestEntry> iterateOverResource(final InputStream in) {
    return new RspTestEntryIterator(in, false);
  }

  /**
   * Equivalent to {@link #iterateOverResource(InputStream)} except that it loads tests explicitly
   * packaged with this class.
   */
  public static Iterator<RspTestEntry> iterateOverLocalTests(final String testFile) throws IOException {
    return new RspTestEntryIterator(RspTestEntry.class.getResourceAsStream(testFile), true);
  }

  private static class RspTestEntryIterator implements Iterator<RspTestEntry> {
    private final Scanner in_;
    private final boolean closeWhenDone_;
    private RspTestEntry next_;
    private boolean inHeader_ = false;
    private boolean inInstance_ = false;
    private Map<String, String> header_;
    private Map<String, String> instance_;

    public RspTestEntryIterator(final InputStream stream, final boolean closeWhenDone) {
      in_ = new Scanner(stream, "UTF-8");
      closeWhenDone_ = closeWhenDone;
    }

    @Override
    public boolean hasNext() {
      loadNext();
      if (next_ == null && closeWhenDone_) {
        in_.close();
      }
      return next_ != null;
    }

    @Override
    public RspTestEntry next() {
      loadNext();
      final RspTestEntry result = next_;
      next_ = null;
      return result;
    }

    private void loadNext() {
      if (next_ != null) {
        return;
      }
      String line;
      while (in_.hasNextLine()) {
        line = in_.nextLine().trim();
        if (line.startsWith("#")) {
          continue;
        }

        final Matcher headerMatcher = HEADER_ENTRY.matcher(line);
        if (headerMatcher.matches()) {
          if (!inHeader_) {
            header_ = new HashMap<>();
            inHeader_ = true;
          }
          header_.put(headerMatcher.group(1), headerMatcher.group(2));
          continue;
        }
        final Matcher namelessHeaderMatcher = NAMELESS_HEADER_ENTRY.matcher(line);
        if (namelessHeaderMatcher.matches()) {
          if (!inHeader_) {
            header_ = new HashMap<>();
            inHeader_ = true;
          }
          header_.put("", namelessHeaderMatcher.group(1));
          continue;
        }
        if (inHeader_ && line.isEmpty()) {
          inHeader_ = false;
          continue;
        }

        final Matcher testMatcher = INSTANCE_ENTRY.matcher(line);
        if (testMatcher.matches()) {
          if (!inInstance_) {
            instance_ = new HashMap<>();
            inInstance_ = true;
          }
          instance_.put(testMatcher.group(1), testMatcher.group(2));
          continue;
        }
        if (inInstance_ && line.isEmpty()) {
          inInstance_ = false;
          next_ =
              new RspTestEntry(Collections.unmodifiableMap(header_),
                  Collections.unmodifiableMap(instance_));
          return;
        }
      }
    }
  }
}
