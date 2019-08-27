// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * <p>
 * Class to handle buffering data prior to passing it through to the native code. It buffers it up
 * into fewer (larger) chunks to avoid incurring marshalling overhead.  The first time a handler is
 * called it will be an {@code InitialUpdate} handler (if present). All subsequent calls are
 * guaranteed to go to standard {@code Update} handlers.  If all of the data can be buffered prior
 * to calling {@link #doFinal()}, then this class will attempt to use the {@code SinglePass} handler
 * if available.
 *
 * <p>
 * The following handlers <em>must</em> be set.
 * <ul>
 * <li>{@link #withUpdater(ArrayStateConsumer)}
 * <li>{@link #withDoFinal(FinalHandlerFunction)}
 * </ul>
 *
 * <p>
 * All {@link ByteBuffer} handlers default to calling their {@link ArrayStateConsumer} equivalents. All
 * InitialUpdate handlers default to calling their Update equivalents.
 * {@link #withSinglePass(ArrayFunction)} defaults to calling the update and doFinal steps.
 *
 * @param T result type
 * @param S state type
 */
// Note: Please consult the "How to Read JML" readme to understand the JML annotations
// in this file (contained in //@ or /*@ @*/ comments).

//@ non_null_by_default
// @NotThreadSafe // Restore once replacement for JSR-305 available
public class InputBuffer<T, S> implements Cloneable {

    //@ // represents initialization state of buffer
    /*@ public model enum BufferState {
      @     Uninitialized, // just constructed, needs update handler and init handler
      @     Ready,         // handlers are set, ready to take data
      @     DataIn,        // data has come in but has only been buffered
      @     HandlerCalled, // either init or update handler has been called
      @     Finalized      // doFinal has been called, cannot take more data until reset
      @ }
      @*/
    
    //@ // safe to call update() except after doFinal() or before setting handlers
    /*@ public normal_behavior
      @     requires true;
      @     ensures (s == BufferState.Ready
      @              || s == BufferState.DataIn
      @              || s == BufferState.HandlerCalled) <==> \result;
      @ public static model pure boolean canTakeData(BufferState s);
      @*/
    
    //@ // safe to reset handlers before taking data or after finishing
    /*@ public normal_behavior
      @     requires true;
      @     ensures (s == BufferState.Uninitialized 
      @              || s == BufferState.Ready 
      @              || s == BufferState.Finalized) <==> \result;
      @ public static model pure boolean canSetHandler(BufferState s);
      @*/
        
    //@ // note: final handler and single array pass can always safely be set
    
    //@ // if firstData is true, then no handler can have been called
    /*@ public normal_behavior
      @   requires true;
      @   ensures s == BufferState.Finalized ==> \result; // we don't care about final state
      @   ensures (s == BufferState.HandlerCalled) ==> \result == !firstData;
      @   ensures (s == BufferState.Uninitialized 
      @            || s == BufferState.Ready
      @            || s == BufferState.DataIn) ==> \result == firstData;
      @ public static model pure helper boolean bufferStateConsistent(BufferState s, boolean firstData);
      @*/
    
    //@ non_null_by_default
    @FunctionalInterface
    public static interface ArrayStateConsumer<S> {
    	//@ public normal_behavior
        //@   requires 0 <= offset && offset < src.length && length <= src.length - offset;
      	//@   assignable state.*;
        //@   ensures true;
        public void accept(/*@ nullable @*/ S state, byte[] src, int offset, int length);
    }

    //@ non_null_by_default
    @FunctionalInterface
    public static interface ArrayFunction<T> {
        //@ public normal_behavior
        //@   requires 0 <= offset && offset <= src.length && length <= src.length - offset;
    	//@   ensures \result != null ==> \fresh(\result);
        //@ pure
        public /*@ nullable @*/ T apply(byte[] src, int offset, int length);
    }

    // provided for specification purposes
    //@ non_null_by_default
    public static interface FinalHandlerFunction<T, R> extends Function<T,R> {
        //@ also
        //@ public normal_behavior
        //@   ensures \result != null ==>\fresh(\result);
        //@ pure
	public /*@ nullable @*/ R apply(/*@ nullable @*/ T t);
    }

    // provided for specification purposes
    //@ non_null_by_default
    @FunctionalInterface
    public static interface ByteBufferFunction<S> extends Function<ByteBuffer, S> {
        //@ also
        //@ public normal_behavior
        //@   assignable bb.position;
        //@   ensures bb.position == bb.limit;
        //@   ensures \result != null ==> \fresh(\result);
        public /*@ nullable @*/ S apply(ByteBuffer bb);
    }

    // provided for specification purposes
    //@ non_null_by_default
    @FunctionalInterface
    public static interface ByteBufferBiConsumer<S> extends BiConsumer<S, ByteBuffer> {
        //@ also
        //@ public normal_behavior
        //@   assignable bb.position;
        //@   ensures bb.position == bb.limit;
        public void accept(/*@ nullable @*/ S state, ByteBuffer bb);
    }
    
    // provided for specification purposes
    //@ non_null_by_default
    @FunctionalInterface
    public static interface StateSupplier<S> extends Supplier<S> {
        //@ also
        //@ public normal_behavior
        //@   ensures \result != null ==> \fresh(\result);
        //@ pure
        public /*@ nullable @*/ S get();
    }

    //@ private invariant 0 <= buffSize;
    //@ spec_public
    private final int buffSize;
    //@ spec_public
    private /*@ non_null @*/ AccessibleByteArrayOutputStream buff;
    //@ public invariant buffSize == buff.limit;
    //@ spec_public
    private boolean firstData = true;
    //@ public invariant firstData ==> bytesProcessed == 0; // converse is not true!
    //@ spec_public
    private /*@ nullable @*/ S state;

    //@ spec_public
    private /*@ nullable @*/ ArrayStateConsumer<S> arrayUpdater;
    //@ spec_public
    private /*@ nullable @*/ FinalHandlerFunction<S, T> finalHandler;
    //@ spec_public
    private /*@ { Consumer.Local<S> } @*/ Consumer<S> stateResetter = (ignored) -> { }; // NOP
    //@ spec_public
    private StateSupplier<S> stateSupplier = () -> null;
    //@ spec_public
    private Optional<Function<S, S>> stateCloner = Optional.empty();
    // If absent, delegates to arrayUpdater
    //@ spec_public
    private Optional<ByteBufferBiConsumer<S>> bufferUpdater = Optional.empty();
    // If absent, delegates to arrayUpdater
    //@ spec_public
    private Optional<ArrayFunction<S>> initialArrayUpdater = Optional.empty();
    // If absent, delegates to bufferUpdater or initialArrayUpdater
    //@ spec_public
    private Optional<ByteBufferFunction<S>> initialBufferUpdater = Optional.empty();
    // If absent, delegates to firstArrayUpdater+finalHandler
    //@ spec_public
    private Optional<ArrayFunction<T>> singlePassArray = Optional.empty();
    
    //@ // Additional state needed in specifications:
    //@ public ghost int bytesReceived;  // total # bytes given to InputBuffer
    //@ public ghost int bytesProcessed; // total # bytes InputBuffer has passed to handlers
    
    //@ public ghost BufferState bufferState;
    
    // should use buff.size() rather than count directly but this appears to be some odd JML bug
    //@ public invariant bytesReceived == bytesProcessed + buff.count;
    
    //@ public invariant bufferStateConsistent(bufferState, firstData);
    
    //@ normal_behavior
    //@   requires 0 < capacity;
    //@   ensures bytesReceived == 0;
    //@   ensures bytesProcessed == 0;
    //@   ensures bufferState == BufferState.Uninitialized;
    //@   ensures firstData;
    //@ also exceptional_behavior
    //@   requires capacity < 0;
    //@   signals_only IllegalArgumentException;
    //@ pure
    InputBuffer(final int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("Capacity must be positive");
        }
        //@ set bufferState = BufferState.Uninitialized;
        buff = new AccessibleByteArrayOutputStream(0, capacity);
        //@ assert buff.size() == 0;
        buffSize = capacity;
        //@ assert bytesReceived == 0;
    }

    /*@ public normal_behavior
      @   requires true;
      @   assignable buff.count, state, state.*, firstData, 
      @              bytesProcessed, bytesReceived, bufferState;
      @   ensures bytesReceived == 0;
      @   ensures \old(bufferState) == BufferState.Uninitialized
      @           ==> bufferState == BufferState.Uninitialized;
      @   ensures \old(bufferState) != BufferState.Uninitialized
      @           ==> bufferState == BufferState.Ready;
      @   ensures firstData;
      @   ensures buff.count == 0;
      @   ensures bytesProcessed == 0;
      @*/
    public void reset() {
        buff.reset();
        firstData = true;
        if (state != null) {
            stateResetter.accept(state);
        }
        state = stateSupplier.get();
        /*@ set bytesReceived = 0;
          @ set bytesProcessed = 0;
          @ set bufferState = ((bufferState == BufferState.Uninitialized)
          @                    ? bufferState : BufferState.Ready);
          @*/
    }

    //@ // optional updater, does not change bufferState
    //@ normal_behavior
    //@   requires canSetHandler(bufferState);
    //@   assignable initialArrayUpdater;
    //@   ensures \result == this && initialArrayUpdater.value == handler;
    public InputBuffer<T, S> withInitialUpdater(final /*@ nullable @*/ ArrayFunction<S> handler) {
        initialArrayUpdater = Optional.ofNullable(handler);
        return this;
    }

    /*@ normal_behavior
      @   requires canSetHandler(bufferState);
      @   assignable arrayUpdater, bufferState;
      @   ensures \result == this && arrayUpdater == handler;    
      @   ensures (\old(bufferState) == BufferState.Uninitialized && handler != null) 
      @           ==> bufferState == BufferState.Ready;
      @   ensures (\old(bufferState) != BufferState.Uninitialized || handler == null)
      @           ==> bufferState == \old(bufferState);
      @*/
    public InputBuffer<T, S> withUpdater(final /*@ nullable @*/ ArrayStateConsumer<S> handler) {
        arrayUpdater = handler;
        /*@ set bufferState = (bufferState == BufferState.Uninitialized && handler != null) 
          @                    ? BufferState.Ready : bufferState;
          @*/
        return this;
    }

    //@ // because buffer updaters are optional, does not change bufferState
    //@ normal_behavior
    //@     requires canSetHandler(bufferState);
    //@     assignable initialBufferUpdater;
    //@     ensures \result == this && initialBufferUpdater.value == handler;
    public InputBuffer<T, S> withInitialUpdater(final /*@ nullable @*/ ByteBufferFunction<S> handler) {
        initialBufferUpdater = Optional.ofNullable(handler);
        return this;
    }
    
    //@ // because buffer updaters are optional, does not change bufferState
    //@ normal_behavior
    //@     requires canSetHandler(bufferState);
    //@     assignable bufferUpdater;
    //@     ensures \result == this && bufferUpdater.value == handler;
    public InputBuffer<T, S> withUpdater(final /*@ nullable @*/ ByteBufferBiConsumer<S> handler) {
        bufferUpdater = Optional.ofNullable(handler);
        return this;
    }

    //@ normal_behavior
    //@     requires true;
    //@     assignable finalHandler;
    //@     ensures \result == this && finalHandler == handler;
    public InputBuffer<T, S> withDoFinal(final FinalHandlerFunction<S, T> handler) {
        finalHandler = handler;
        return this;
    }

    //@ normal_behavior
    //@     requires true;
    //@     assignable singlePassArray;
    //@     ensures \result == this && singlePassArray.value == handler;
    public InputBuffer<T, S> withSinglePass(final /*@ nullable @*/ ArrayFunction<T> handler) {
        singlePassArray = Optional.ofNullable(handler);
        return this;
    }

    //@ normal_behavior
    //@     requires true;
    //@     assignable stateCloner;
    //@     ensures \result == this && stateCloner.value == cloner;
    public InputBuffer<T, S> withStateCloner(final /*@ nullable @*/ Function<S, S> cloner) {
        stateCloner = Optional.ofNullable(cloner);
        return this;
    }

    //@ normal_behavior
    //@     requires true;
    //@     assignable stateResetter;
    //@     ensures \result == this && stateResetter == resetter;
    public InputBuffer<T, S> withStateResetter(final /*@ { Consumer.Local<S> } @*/ Consumer<S> resetter) {
        stateResetter = resetter;
        return this;
    }

    /*@ normal_behavior
      @     requires canSetHandler(bufferState);
      @     assignable stateSupplier;
      @     ensures \result == this && stateSupplier == supplier;
      @*/
    public InputBuffer<T, S> withInitialStateSupplier(final StateSupplier<S> supplier) {
        stateSupplier = supplier;
        return this;
    }

    /*@ private normal_behavior
      @   requires 0 <= offset && 0 <= length && offset <= arr.length - length;
      @   requires canTakeData(bufferState);
      @   {|
      @       requires buffSize - buff.count >= length;
      @       assignable buff.count, bytesReceived, bufferState;
      @       ensures \result;
      @       ensures bytesReceived == \old(bytesReceived) + length;
      @       ensures buff.count == \old(buff.count) + length;
      @       ensures \old(bufferState) == BufferState.Ready 
      @                ==> bufferState == BufferState.DataIn;
      @       ensures \old(bufferState) != BufferState.Ready
      @                ==> bufferState == \old(bufferState);
      @       also
      @       requires buffSize - buff.count < length;
      @       assignable \nothing;
      @       ensures !\result;
      @   |}
      @ also
      @ private exceptional_behavior
      @   requires buff.count <= buffSize - length;
      @   requires offset < 0 || length < 0 || offset > arr.length - length;
      @   assignable \nothing;
      @   signals_only ArrayIndexOutOfBoundsException;
      @*/
    /**
     * Copies all requested data from {@code arr} into {@link #buff} if an only if there is
     * sufficient space. Returns {@code true} if the data was copied.
     * @return {@code true} if there was sufficient space in the buffer and data was copied.
     */
    private boolean fillBuffer(final byte[] arr, final int offset, final int length) {
        // Overflow safe comparison. Length might still be negative, but we'll catch
        // that later.
        if (buffSize - buff.size() < length) {
            return false;
        }        
        try {
            buff.write(arr, offset, length);
        } catch (IndexOutOfBoundsException ex) {
            throw new ArrayIndexOutOfBoundsException(ex.toString());
        }
        //@ set bytesReceived = bytesReceived + length;
	//@ set bufferState = (bufferState == BufferState.Ready) ? BufferState.DataIn : bufferState;
        return true;
    }

    /*@ private normal_behavior
      @   requires canTakeData(bufferState);
      @   {|
      @       requires buffSize - buff.count >= 1;
      @       assignable buff.count, bytesReceived, bufferState;
      @       ensures \result;
      @       ensures bytesReceived == \old(bytesReceived) + 1;
      @       ensures buff.count == \old(buff.count) + 1;
      @       ensures \old(bufferState) == BufferState.Ready
      @                ==> bufferState == BufferState.DataIn;
      @       ensures \old(bufferState) != BufferState.Ready
      @                ==> bufferState == \old(bufferState);
      @       also
      @       requires buffSize - buff.count < 1;
      @       assignable \nothing;
      @       ensures !\result;
      @   |}
      @ also
      @ private exceptional_behavior
      @   requires buff.count <= buffSize - 1;
      @   assignable \nothing;
      @   signals_only ArrayIndexOutOfBoundsException;
      @*/
    /**
     * Copies {@code val} into {@link #buff} if an only if there is
     * sufficient space. Returns {@code true} if the data was copied.
     * @return {@code true} if there was sufficient space in the buffer and data was copied.
     */
    private boolean fillBuffer(final byte val) {
        // Overflow safe comparison.
        if (buffSize - buff.size() < 1) {
            return false;
        }
        try {
            buff.write(val);
        } catch (IndexOutOfBoundsException ex) {
            throw new ArrayIndexOutOfBoundsException(ex.toString());
        }
        //@ set bytesReceived = bytesReceived + 1;
        //@ set bufferState = (bufferState == BufferState.Ready) ? BufferState.DataIn : bufferState;
        return true;
    }

    /*@ private normal_behavior
      @   old int length = src.remaining();
      @   requires canTakeData(bufferState);
      @   {|
      @       requires buffSize - buff.count >= length;
      @       assignable buff.count, bytesReceived, src.position, bufferState;
      @       ensures \result;
      @       ensures bytesReceived == \old(bytesReceived) + length;
      @       ensures buff.count == \old(buff.count) + length;
      @       ensures src.position == src.limit;
      @       ensures \old(bufferState) == BufferState.Ready 
      @                ==> bufferState == BufferState.DataIn;
      @       ensures \old(bufferState) != BufferState.Ready
      @                ==> bufferState == \old(bufferState);
      @       ensures canTakeData(bufferState);
      @       also
      @       requires buffSize - buff.count < length;
      @       assignable \nothing;
      @       ensures !\result;
      @   |}
      @*/
    /**
     * Copies all requested data from {@code src} into {@link #buff} if an only if there is
     * sufficient space. Returns {@code true} if the data was copied.
     * @return {@code true} if there was sufficient space in the buffer and data was copied.
     */
    private boolean fillBuffer(final ByteBuffer src) {
        final int length = src.remaining();
        // Overflow safe comparison. Length might still be negative, but we'll catch
        // that later.
        if (buffSize - buff.size() < length) {
            return false;
        }
        buff.write(src);
        //@ set bytesReceived = bytesReceived + length;
        //@ set bufferState = (bufferState == BufferState.Ready) ? BufferState.DataIn : bufferState;
        return true;
    }

    /*@ private normal_behavior
      @   old boolean nonEmpty = buff.count > 0;
      @   requires canTakeData(bufferState);
      @   {|
      @       requires !nonEmpty && !forceInit;
      @       assignable \nothing;
      @       also
      @       requires arrayUpdater != null;
      @       requires nonEmpty || forceInit;
      @       assignable firstData, state, state.*, bytesProcessed, buff.count, bufferState;
      @       ensures !firstData;
      @       ensures !\old(firstData) ==> state == \old(state);
      @       ensures bufferState == BufferState.HandlerCalled;
      @       ensures bytesProcessed == bytesReceived;
      @       ensures buff.count == 0;
      @   |}
      @*/
    /**
     * If there is data in {@link #buff} then delivers it all to the appropriate underlying handler
     * and empties {@link #buff}. If {@link #buff} is empty then this method is a NOP <em>unless</em>
     * no data has been previously passed to a handler (e.g., {@link #firstData} is {@code true}) and
     * {@code forceInit} is also {@code true}.
     * 
     * @param forceInit if {@code true} guarantees that {@link #state} will be initialized (if
     *        appropriate) by the time this method returns.
     */
    private void processBuffer(boolean forceInit) {
        //@ ghost int oldSize = buff.size();
        if (firstData && (forceInit || buff.size() > 0)) {
            if (initialArrayUpdater.isPresent()) {
                state = initialArrayUpdater.get().apply(buff.getDataBuffer(), 0, buff.size());
                buff.reset();
                //@ set bytesProcessed = bytesProcessed + oldSize;
            } else {
                state = stateSupplier.get();
            }
            //@ set bufferState = BufferState.HandlerCalled;
            firstData = false;
        }
        if (buff.size() > 0) {
            arrayUpdater.accept(state, buff.getDataBuffer(), 0, buff.size());
            //@ set bufferState = BufferState.HandlerCalled;
            //@ set bytesProcessed = bytesProcessed + oldSize;
            buff.reset();
        }
    }

    /*@ public normal_behavior
      @   requires canTakeData(bufferState);
      @   requires arrayUpdater != null && bufferUpdater.isPresent();
      @   assignable src.position, state, state.*, bytesProcessed, 
      @              bytesReceived, firstData, buff.count, bufferState;
      @   ensures bytesReceived == \old(bytesReceived + src.remaining());
      @   ensures src.position == src.limit;
      @   ensures canTakeData(bufferState);
      @*/
    public void update(final ByteBuffer src) {
        try {
            //@ ghost int length = src.remaining();

            // We delegate to the equivalent array handler in any of these cases:
            // 1. This is not a direct ByteBuffer
            // 2. firstData is true and we don't have any buffer handlers
            // 3. firstData is false and we don't have a middleBuffer handler
            if (!src.isDirect() ||
                    (firstData && !initialBufferUpdater.isPresent() && !bufferUpdater.isPresent()) ||
                    (!firstData && !bufferUpdater.isPresent())) {
                final ShimArray shim = new ShimArray(src);
                update(shim.array, shim.offset, shim.length);
                return;
            }
            if (fillBuffer(src)) {
                return;
            }
            processBuffer(false);
            if (fillBuffer(src)) {
                return;
            }

            //@ // to ensure proper ordering, we must guarantee that the buffer is empty
            //@ // if we are processing input (src) directly
            //@ assert buff.count == 0;

            if (firstData) {
                if (initialBufferUpdater.isPresent()) {
                    state = initialBufferUpdater.get().apply(src.slice());
                } else {
                    state = stateSupplier.get();
                    bufferUpdater.get().accept(state, src.slice());
                }
            } else {
                bufferUpdater.get().accept(state, src.slice());
            }
            firstData = false;
	    //@ set bufferState = BufferState.HandlerCalled;
            //@ set bytesProcessed = bytesProcessed + length;
            //@ set bytesReceived = bytesReceived + length;
        } finally {
            src.position(src.limit());
        }
    }

    /*@ public normal_behavior
      @   requires canTakeData(bufferState);
      @   requires 0 <= offset && 0 <= length && length <= src.length - offset;
      @   requires arrayUpdater != null;
      @   assignable state, state.*, buff.count, firstData, bytesProcessed, 
      @              bytesReceived, bufferState;
      @   ensures bytesReceived == \old(bytesReceived) + length;
      @   ensures canTakeData(bufferState);
      @ also
      @ public exceptional_behavior
      @   requires buff.count <= buffSize - length;
      @   requires offset < 0 || length < 0 || length > src.length - offset;
      @   assignable \nothing;
      @   signals_only ArrayIndexOutOfBoundsException;
      @*/
    public void update(final byte[] src, final int offset, final int length) {
        if (fillBuffer(src, offset, length)) {
            return;
        }
        processBuffer(false);
        if (fillBuffer(src, offset, length)) {
            return;
        }

        //@ // to ensure proper ordering, we must guarantee that the buffer is empty
        //@ // if we are processing input (src) directly
        //@ assert buff.count == 0;

        if (firstData) {
            if (initialArrayUpdater.isPresent()) {
                state = initialArrayUpdater.get().apply(src, offset, length);
            } else {
                state = stateSupplier.get();
                arrayUpdater.accept(state, src, offset, length);
            }
        } else {
            arrayUpdater.accept(state, src, offset, length);
        }
        firstData = false;
        //@ set bufferState = BufferState.HandlerCalled;
        //@ set bytesProcessed = bytesProcessed + length;
        //@ set bytesReceived = bytesReceived + length;
    }

    /*@ public normal_behavior
      @   requires canTakeData(bufferState);
      @   requires arrayUpdater != null;
      @   assignable state, state.*, buff.count, firstData, bytesProcessed,
      @              bytesReceived, bufferState;
      @   ensures bytesReceived == \old(bytesReceived) + 1;
      @   ensures canTakeData(bufferState);
      @ also
      @ public exceptional_behavior
      @   requires buff.count <= buffSize - 1;
      @   assignable \nothing;
      @   signals_only ArrayIndexOutOfBoundsException;
      @*/
    public void update(final byte val) {
        if (fillBuffer(val)) {
            return;
        }
        processBuffer(false);
        if (fillBuffer(val)) {
            return;
        }

        // We explicitly do not support capacities of zero where we cannot even append a single byte.
        throw new AssertionError("Unreachable code. Cannot buffer even a single byte");
    }

    //@ public normal_behavior
    //@   requires canTakeData(bufferState);
    //@   requires arrayUpdater != null && finalHandler != null;
    //@   assignable state, state.*, bytesProcessed, firstData, buff.count;
    //@   assignable bufferState;
    //@   ensures \old(!firstData || !singlePassArray.isPresent()) ==> bytesProcessed == bytesReceived;
    //@   // Since singlePass path doesn't empty buffer, we can't both update bytesProcessed
    //@   // and maintain the invariant that bufferSize + bytesProcessed == bytesReceived.
    //@   // This is okay, since if bufferState is Finalized, more data cannot be entered anyway.
    //@   ensures \old(firstData && singlePassArray.isPresent()) ==> bytesProcessed == 0;
    //@   ensures bufferState == BufferState.Finalized;
    public /*@ nullable @*/ T doFinal() {
        if (!firstData || !singlePassArray.isPresent()) {
            processBuffer(true);
            //@ set bufferState = BufferState.Finalized;
            //@ assert bytesProcessed == bytesReceived;
            return finalHandler.apply(state);
        } else {
            //@ set bufferState = BufferState.Finalized;
            //@ assert buff.size() == bytesReceived;
            return singlePassArray.get().apply(buff.getDataBuffer(), 0, buff.size());
        }
    }

    /**
     * WARNING! This only does a shallow copy of the handlers, so any which refer to external state
     * (so, any values not passed in as arguments) may be incorrect and need to be fixed prior to
     * use.
     */
    //@ also public behavior
    //@   ensures true;
    //@   signals_only CloneNotSupportedException;
    //@ pure
    @Override
    protected Object clone() throws CloneNotSupportedException {
        if (!stateCloner.isPresent()) {
            throw new CloneNotSupportedException("No stateCloner configured");
        }
        @SuppressWarnings("unchecked")
        final InputBuffer<T, S> clonedObject = (InputBuffer<T, S>) super.clone();

        clonedObject.state = state != null ? stateCloner.get().apply(state) : null;
        clonedObject.buff = buff.clone();

        return clonedObject;
    }

    /**
     * An array view over a bytebuffer - either directly aliasing the underlying bytebuffer, or a
     * copy of the byte buffer's data.
     */
    private static class ShimArray {
        private final ByteBuffer backingBuffer;
        public final byte[] array;
        public final int offset, length;

        //@ public normal_behavior
        //@     requires true;
        //@     ensures 0 <= offset;
        //@     ensures length == buffer.limit - buffer.position;
        //@     ensures length <= array.length - offset;
        //@ also
        //@ private normal_behavior
        //@     ensures \fresh(backingBuffer);
        //@     ensures backingBuffer.position == 0;
        //@ pure
        public ShimArray(final ByteBuffer buffer) {
            this.backingBuffer = buffer.slice();
            this.length = backingBuffer.limit();

            final boolean hasArray = backingBuffer.hasArray();
            /*@ nullable @*/ byte[] tmpArray = hasArray ? backingBuffer.array() : null;
            if (tmpArray == null) {
                tmpArray = new byte[length];
                backingBuffer.duplicate().get(tmpArray);
                offset = 0;
            } else {
                //@ assert backingBuffer.position() == 0;  // Note, this means the following line can be simplified.
                offset = backingBuffer.arrayOffset() + backingBuffer.position();
            }

            this.array = tmpArray;
        }
    }
}
