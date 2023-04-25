// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Loader.RESOURCE_JANITOR;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongConsumer;

class NativeResource {
  /** For tests. Makes a best-effort attempt to awaken any sleeping cleaner threads. */
  @SuppressWarnings("unused") // invoked reflectively
  private static void wakeCleaner() {
    RESOURCE_JANITOR.wake();
  }

  private static final class Cell extends ReentrantReadWriteLock {
    private static final long serialVersionUID = 1L;
    // Debug stuff
    private static final boolean FREE_TRACE_DEBUG = DebugFlag.FREETRACE.isEnabled();
    private Throwable creationTrace;
    private Throwable freeTrace;
    // End debug stuff

    // @GuardedBy("this") // Restore once replacement for JSR-305 available
    private final long ptr;
    private final LongConsumer releaser;
    private final boolean isThreadSafe;
    // @GuardedBy("this") // Restore once replacement for JSR-305 available
    private boolean released;

    private Cell(final long ptr, final LongConsumer releaser, boolean isThreadSafe) {
      if (ptr == 0) {
        throw new AssertionError("ptr must not be equal to zero");
      }
      this.ptr = ptr;
      this.releaser = releaser;
      this.released = false;
      this.isThreadSafe = isThreadSafe;
      this.creationTrace = buildFreeTrace("Created", null);
    }

    private CloseableLock getLock(boolean writeLock) {
      if (!isThreadSafe || writeLock) {
        return new CloseableLock(writeLock());
      } else {
        return new CloseableLock(readLock());
      }
    }

    @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
    public void release() {
      try (CloseableLock lock = getLock(true)) {
        if (released) return;

        released = true;
        freeTrace = buildFreeTrace("Freed", creationTrace);
        releaser.accept(ptr);
      }
    }

    @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
    public long take() {
      try (CloseableLock lock = getLock(true)) {
        assertNotFreed();
        released = true;
        freeTrace = buildFreeTrace("Freed", creationTrace);
        return ptr;
      }
    }

    @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
    public boolean isReleased() {
      try (CloseableLock lock = getLock(true)) {
        return released;
      }
    }

    /**
     * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
     * the result.
     */
    // @CheckReturnValue // Restore once replacement for JSR-305 available
    @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
    public <T, X extends Throwable> T use(MiscInterfaces.ThrowingLongFunction<T, X> function)
        throws X {
      try (CloseableLock lock = getLock(false)) {
        assertNotFreed();
        return function.apply(ptr);
      }
    }

    private void assertNotFreed() {
      if (released) {
        throw new IllegalStateException("Use after free", freeTrace);
      }
    }

    private static Throwable buildFreeTrace(final String message, final Throwable cause) {
      if (!FREE_TRACE_DEBUG) {
        return null;
      }
      return new RuntimeCryptoException(
          message + " in Thread " + Thread.currentThread().getName(), cause);
    }

    // ReentrantReadWriteLock is serializable which forces us to pretend to be serializable.
    // We inherit from ReentrantReadWriteLock because it is supposedly a lower-cost way of managing
    // locks.
    // However, we cannot be savely serialized because there is no safe way to save our native
    // state.
    // So, we prevent any attempt to serialize ourselves by throwing an exception.
    private void writeObject(final ObjectOutputStream out) throws IOException {
      throw new NotSerializableException("NativeResource");
    }

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
      throw new NotSerializableException("NativeResource");
    }

    private void readObjectNoData() throws ObjectStreamException {
      throw new NotSerializableException("NativeResource");
    }
  }

  private static final class CloseableLock implements AutoCloseable {
    private final Lock lock;

    CloseableLock(Lock lock) {
      this.lock = lock;
      this.lock.lock();
    }

    @Override
    public void close() {
      lock.unlock();
    }
  }

  private final Cell cell;
  private final Janitor.Mess mess;

  protected NativeResource(long ptr, LongConsumer releaser) {
    this(ptr, releaser, false);
  }

  protected NativeResource(long ptr, LongConsumer releaser, boolean isThreadSafe) {
    cell = new Cell(ptr, releaser, isThreadSafe);

    mess = RESOURCE_JANITOR.register(this, cell::release);
  }

  boolean isReleased() {
    return cell.isReleased();
  }

  /**
   * Calls the supplied {@link MiscInterfaces.ThrowingLongFunction} passing in the raw handle as a
   * parameter and return the result.
   */
  // @CheckReturnValue // Restore once replacement for JSR-305 available
  public <T, X extends Throwable> T use(MiscInterfaces.ThrowingLongFunction<T, X> function)
      throws X {
    return cell.use(function);
  }

  /**
   * Calls the supplied {@link MiscInterfaces.ThrowingLongConsumer} passing in the raw handle as a
   * parameter.
   */
  public <X extends Throwable> void useVoid(MiscInterfaces.ThrowingLongConsumer<X> function)
      throws X {
    @SuppressWarnings("unused")
    Object unused =
        cell.use(
            ptr -> {
              function.accept(ptr);
              return null;
            });
  }

  /**
   * Returns the raw pointer and passes all responsibility to releasing it to the caller.
   *
   * @return ptr
   */
  // @CheckReturnValue // Restore once replacement for JSR-305 available
  long take() {
    long result = cell.take();
    mess.clean();
    return result;
  }

  void release() {
    mess.clean();
  }
}
