package com.amazon.corretto.crypto.provider;

/**
 * Collections of various small internal use interfaces which don't warrant their own file.
 */
final class MiscInterfaces {
    @FunctionalInterface
    interface ThrowingLongFunction<T, X extends Throwable> {
        T apply(long value) throws X;
    }

    @FunctionalInterface
    interface ThrowingLongConsumer<X extends Throwable> {
        void accept(long value) throws X;
    }

    @FunctionalInterface
    interface ThrowingToLongBiFunction<T, U, X extends Throwable> {
        long applyAsLong(T t, U u) throws X;
    }
}
