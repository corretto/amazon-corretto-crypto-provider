// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Loader.RESOURCE_JANITOR;

import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;

class NativeResource {
    /**
     * For tests. Makes a best-effort attempt to awaken any sleeping cleaner threads.
     */
    @SuppressWarnings("unused") // invoked reflectively
    private static void wakeCleaner() {
        RESOURCE_JANITOR.wake();
    }

    private static final class Cell extends ReentrantLock {
        private static final long serialVersionUID = 1L;
        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private final long ptr;
        private final LongConsumer releaser;
        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private boolean released;

        private Cell(final long ptr, final LongConsumer releaser) {
            if (ptr == 0) {
              throw new AssertionError("ptr must not be equal to zero");
            }
            this.ptr = ptr;
            this.releaser = releaser;
            this.released = false;
        }

        public void release() {
            lock();
            try {
                if (released) return;

                released = true;
                releaser.accept(ptr);
            } finally {
                unlock();
            }
        }

        public long take() {
            lock();
            try {
                if (released) {
                    throw new IllegalStateException("Use after free");
                }

                released = true;
                return ptr;
            } finally {
                unlock();
            }
        }

        public boolean isReleased() {
            lock();
            try {
                return released;
            } finally {
                unlock();
            }
        }

        /**
         * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
         * the result.
         */
        // @CheckReturnValue // Restore once replacement for JSR-305 available
        public <T> T use(LongFunction<T> function) {
            lock();
            try {
                if (released) {
                    throw new IllegalStateException("Use after free");
                }
                return function.apply(ptr);
            } finally {
                unlock();
            }
        }
    }

    private final Cell cell;
    private final Janitor.Mess mess;

    protected NativeResource(long ptr, LongConsumer releaser) {
        cell = new Cell(ptr, releaser);

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
