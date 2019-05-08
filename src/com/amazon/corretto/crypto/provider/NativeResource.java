// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;

class NativeResource {
    private static final Janitor RESOURCE_JANITOR = new Janitor();

    /**
     * For tests. Makes a best-effort attempt to awaken any sleeping cleaner threads.
     */
    @SuppressWarnings("unused") // invoked reflectively
    private static void wakeCleaner() {
        RESOURCE_JANITOR.wake();
    }

    private static final class Cell extends ReentrantReadWriteLock {
        private static final long serialVersionUID = 1L;
        private final boolean threadSafe;
        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private final long ptr;
        private final LongConsumer releaser;
        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private boolean released;

        private Cell(final long ptr, final LongConsumer releaser, boolean threadSafe) {
            if (ptr == 0) {
              throw new AssertionError("ptr must not be equal to zero");
            }
            this.ptr = ptr;
            this.releaser = releaser;
            this.released = false;
            this.threadSafe = threadSafe;
        }

        /**
         * Returns an appropriate lock for use when using but not releasing the underlying resource.
         * Returns {@link #readLock()} if {@link #threadSafe} is {@code true}, else returns {@link #writeLock()}.\
         */
        private Lock normalLock() {
            return threadSafe ? readLock() : writeLock();
        }

        public void release() {
            writeLock().lock();
            try {
                if (released) return;

                released = true;
                releaser.accept(ptr);
            } finally {
                writeLock().unlock();
            }
        }

        public long take() {
            writeLock().lock();
            try {
                if (released) {
                    throw new IllegalStateException("Use after free");
                }

                released = true;
                return ptr;
            } finally {
                writeLock().unlock();
            }
        }

        public boolean isReleased() {
            normalLock().lock();
            try {
                return released;
            } finally {
                normalLock().unlock();
            }
        }

        /**
         * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
         * the result.
         */
        // @CheckReturnValue // Restore once replacement for JSR-305 available
        public <T> T use(LongFunction<T> function) {
            normalLock().lock();
            try {
                if (released) {
                    throw new IllegalStateException("Use after free");
                }
                return function.apply(ptr);
            } finally {
                normalLock().unlock();
            }
        }
    }

    private final Cell cell;
    private final Janitor.Mess mess;

    protected NativeResource(long ptr, LongConsumer releaser) {
        this(ptr, releaser, false);
    }

    protected NativeResource(long ptr, LongConsumer releaser, boolean threadSafe) {
        cell = new Cell(ptr, releaser, threadSafe);

        mess = RESOURCE_JANITOR.register(this, cell::release);
    }

    boolean isReleased() {
        return cell.isReleased();
    }

    /**
     * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
     * the result.
     */
    // @CheckReturnValue // Restore once replacement for JSR-305 available
    <T> T use(LongFunction<T> function) {
        return cell.use(function);
    }

    /**
     * Calls the supplied {@link LongConsumer} passing in the raw handle as a parameter.
     */
    void useVoid(LongConsumer function) {
        @SuppressWarnings("unused")
        Object unused = cell.use(ptr -> {
            function.accept(ptr);
            return null;
        });
    }

    /**
     * Returns the raw pointer and passes all responsibility to releasing it to the caller.
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
