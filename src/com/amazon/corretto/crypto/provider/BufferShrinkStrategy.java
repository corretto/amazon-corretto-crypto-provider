package com.amazon.corretto.crypto.provider;

/**
 * Represents a strategy for downsizing/shrinking a reusable buffer.
 * For example, {@link AccessibleByteArrayOutputStream} holds a reusable buffer which grows as needed
 * to accommodate different sized payloads. If this buffer never shrinks, it may waste space (for example
 * if we see one rare very large payload but subsequent payloads are small, the buffer will remain unnecessarily
 * large).
 * Note: implementations are usually stateful and thus instances cannot be safely shared.
 */
public interface BufferShrinkStrategy {
    // TODO: could return 'recommended buffer size' instead of boolean. Value/simplicity?
    // TODO: should the strategy also handle growth?

    /**
     * Buffer owners should call this after consumption of every payload.
     * E.g. handlePayload(byte[] payload) {
     *   ... maybe grow buffer
     *   ... encrypt
     *   if (shouldShrink(payload.length, buffer.length)) shrinkBuf();
     * }
     * @param payloadSize The size of the payload processed.
     * @param bufferSize The size of the buffer.
     * @return true if the strategy recommends shrinking the buffer. false otherwise.
     */
    boolean shouldShrink(int payloadSize, int bufferSize);

    /**
     * Shrink the buffer when it is too large for the payload ('over-sized') N times in a row.
     * E.g. if an 800KB payload grows the buffer to 1MB, we shrink the buffer after seeing N consecutive
     * payloads under 500KB.
     */
    class BasicThreshold implements BufferShrinkStrategy {
        private final int timesOversizedThreshold;
        private int timesOversized = 0;

        public BasicThreshold() {
            this.timesOversizedThreshold = 1024;
        }

        public BasicThreshold(int timesOversizedThreshold) {
            this.timesOversizedThreshold = timesOversizedThreshold;
        }

        @Override
        public boolean shouldShrink(int payloadSize, int bufferSize) {
            if (bufferSize / 2 > payloadSize) {
                // The buffer was over-sized for this usage.
                if (timesOversized++ > timesOversizedThreshold) {
                    timesOversized = 0;
                    return true;
                }
            } else {
                // Buffer was not over-sized, reset counter.
                timesOversized = 0;
            }
            return false;
        }
    }

    /**
     * Similar to {@link BasicThreshold}, but the threshold starts at 1 and increases
     * to the chosen limit. This has the benefit of being somewhat adaptive; it starts
     * out eager to shrink quickly after a large payload, but slows down every time
     * re-growth is needed, up to the chosen limit.
     */
    class IncreasingThreshold implements BufferShrinkStrategy {
        private final int maxOversizedThreshold;
        private int timesOversizedThreshold = 1;
        private int timesOversized = 0;
        private int previousBufferSize = Integer.MAX_VALUE;

        public IncreasingThreshold() {
            this.maxOversizedThreshold = 1024;
        }

        public IncreasingThreshold(int maxOversizedThreshold) {
            this.maxOversizedThreshold = maxOversizedThreshold;
        }

        @Override
        public boolean shouldShrink(int payloadSize, int bufferSize) {
            if (bufferSize > previousBufferSize) {
                // Every time we need to grow, make it harder to shrink in the future (up to a limit).
                timesOversizedThreshold = Math.min(maxOversizedThreshold, timesOversizedThreshold * 2);
            }
            previousBufferSize = bufferSize;

            if (bufferSize / 2 > payloadSize) {
                // The buffer was over-sized for this usage.
                if (timesOversized++ > timesOversizedThreshold) {
                    timesOversized = 0;
                    return true;
                }
            } else {
                // Buffer was not over-sized, reset counter.
                timesOversized = 0;
            }

            return false;
        }
    }
}
