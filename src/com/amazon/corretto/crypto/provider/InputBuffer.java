// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Class to handle buffering data prior to passing it through to the native code. It buffers it up
 * into fewer (larger) chunks to avoid incurring marshalling overhead. The first time a handler is
 * called it will be an {@code InitialUpdate} handler (if present). All subsequent calls are
 * guaranteed to go to standard {@code Update} handlers. If all data can be buffered prior to
 * calling {@link #doFinal()}, then this class will attempt to use the {@code SinglePass} handler if
 * available.
 *
 * <p>The following handlers <em>must</em> be set.
 *
 * <ul>
 *   <li>{@link #withUpdater(ArrayStateConsumer)}
 *   <li>{@link #withDoFinal(FinalHandlerFunction)}
 * </ul>
 *
 * <p>All {@link ByteBuffer} handlers default to calling their {@link ArrayStateConsumer}
 * equivalents. All InitialUpdate handlers default to calling their Update equivalents. {@link
 * #withSinglePass(ArrayFunction)} defaults to calling the update and doFinal steps.
 *
 * @param <R> result type
 * @param <S> state type
 * @param <X> exception which can be thrown upon completion
 */
public class InputBuffer<R, S, X extends Throwable> implements Cloneable {

  @FunctionalInterface
  public interface ArrayStateConsumer<INPUT_CONTEXT_TYPE> { // IProcessArrayData_WithInputContext_NoReturn
    void accept(INPUT_CONTEXT_TYPE state, byte[] src, int offset, int length);
  }

  @FunctionalInterface
  public interface ArrayFunction<RETURN_TYPE, EXCEPTION extends Throwable> { // IProcessArrayData_NoInputContext_WithReturn
    RETURN_TYPE apply(byte[] src, int offset, int length) throws EXCEPTION;
  }

  public interface FinalHandlerFunction<STATE, RESULT, EXCEPTION extends Throwable> { // IFinalHandler_WithInputContext_WithReturn
    RESULT apply(STATE t) throws EXCEPTION;
  }

  @FunctionalInterface
  public interface ByteBufferFunction<STATE> extends Function<ByteBuffer, STATE> { // IProcessBufferData_NoInputContext_WithReturn
    STATE apply(ByteBuffer bb);
  }

  @FunctionalInterface
  public interface ByteBufferBiConsumer<STATE> extends BiConsumer<STATE, ByteBuffer> {  // IProcessBufferData_WithInputContext_NoReturn
    void accept(STATE state, ByteBuffer bb);
  }

  @FunctionalInterface
  public interface StateSupplier<STATE> extends Function<STATE, STATE> { // IStateSupplier
    STATE apply(STATE state);
  }

  private final int buffSize;
  private AccessibleByteArrayOutputStream buff;
  private boolean firstData = true;
  private S state;

  private ArrayStateConsumer<S> arrayUpdater;
  private FinalHandlerFunction<S, R, X> finalHandler;
  private StateSupplier<S> stateSupplier = (oldState) -> oldState;
  private Optional<Function<S, S>> stateCloner = Optional.empty();
  // If absent, delegates to arrayUpdater
  private Optional<ByteBufferBiConsumer<S>> bufferUpdater = Optional.empty();
  // If absent, delegates to arrayUpdater
  private Optional<ArrayFunction<S, RuntimeException>> initialArrayUpdater = Optional.empty();
  // If absent, delegates to bufferUpdater or initialArrayUpdater
  private Optional<ByteBufferFunction<S>> initialBufferUpdater = Optional.empty();
  // If absent, delegates to firstArrayUpdater+finalHandler
  private Optional<ArrayFunction<R, X>> singlePassArray = Optional.empty();

  InputBuffer(final int capacity) {
    if (capacity <= 0) {
      throw new IllegalArgumentException("Capacity must be positive");
    }
    buff = new AccessibleByteArrayOutputStream(0, capacity);
    buffSize = capacity;
  }

  public void reset() {
    buff.reset();
    firstData = true;
  }

  public int size() {
    return buff.size();
  }

  public InputBuffer<R, S, X> withInitialUpdater(final ArrayFunction<S, RuntimeException> handler) {
    initialArrayUpdater = Optional.ofNullable(handler);
    return this;
  }

  public InputBuffer<R, S, X> withUpdater(final ArrayStateConsumer<S> handler) {
    arrayUpdater = handler;
    return this;
  }

  public InputBuffer<R, S, X> withInitialUpdater(final ByteBufferFunction<S> handler) {
    initialBufferUpdater = Optional.ofNullable(handler);
    return this;
  }

  public InputBuffer<R, S, X> withUpdater(final ByteBufferBiConsumer<S> handler) {
    bufferUpdater = Optional.ofNullable(handler);
    return this;
  }

  public InputBuffer<R, S, X> withDoFinal(final FinalHandlerFunction<S, R, X> handler) {
    finalHandler = handler;
    return this;
  }

  public InputBuffer<R, S, X> withSinglePass(final ArrayFunction<R, X> handler) {
    singlePassArray = Optional.ofNullable(handler);
    return this;
  }

  public InputBuffer<R, S, X> withStateCloner(final Function<S, S> cloner) {
    stateCloner = Optional.ofNullable(cloner);
    return this;
  }

  public InputBuffer<R, S, X> withInitialStateSupplier(final StateSupplier<S> supplier) {
    stateSupplier = supplier;
    return this;
  }

  /**
   * Copies all requested data from {@code arr} into {@link #buff} if and only if there is sufficient
   * space. Returns {@code true} if the data was copied.
   *
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

    return true;
  }

  /**
   * Copies {@code val} into {@link #buff} if and only if there is sufficient space. Returns {@code
   * true} if the data was copied.
   *
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
    return true;
  }

  /**
   * Copies all requested data from {@code src} into {@link #buff} if and only if there is sufficient
   * space. Returns {@code true} if the data was copied.
   *
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
    return true;
  }

  /**
   * If there is data in {@link #buff} then delivers it all to the appropriate underlying handler
   * and empties {@link #buff}. If {@link #buff} is empty then this method is a NOP <em>unless</em>
   * no data has been previously passed to a handler (e.g., {@link #firstData} is {@code true}) and
   * {@code forceInit} is also {@code true}.
   *
   * @param forceInit if {@code true} guarantees that {@link #state} will be initialized (if
   *     appropriate) by the time this method returns.
   */
  private void processBuffer(boolean forceInit) {
    if (firstData && (forceInit || buff.size() > 0)) {
      if (initialArrayUpdater.isPresent()) {
        state = initialArrayUpdater.get().apply(buff.getDataBuffer(), 0, buff.size());
        buff.reset();
      } else {
        state = stateSupplier.apply(state);
      }
      firstData = false;
    }
    if (buff.size() > 0) {
      arrayUpdater.accept(state, buff.getDataBuffer(), 0, buff.size());
      buff.reset();
    }
  }

  public void update(final ByteBuffer src) {
    try {
      // We delegate to the equivalent array handler in any of these cases:
      // 1. This is not a direct ByteBuffer
      // 2. firstData is true, and we don't have any buffer handlers
      // 3. firstData is false, and we don't have a middleBuffer handler
      if (!src.isDirect()
          || (firstData && !initialBufferUpdater.isPresent() && !bufferUpdater.isPresent())
          || (!firstData && !bufferUpdater.isPresent())) {
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

      if (firstData) {
        if (initialBufferUpdater.isPresent()) {
          state = initialBufferUpdater.get().apply(src.slice());
        } else {
          state = stateSupplier.apply(state);
          bufferUpdater.get().accept(state, src.slice());
        }
      } else {
        bufferUpdater.get().accept(state, src.slice());
      }
      firstData = false;
    } finally {
      src.position(src.limit());
    }
  }

  public void update(final byte[] src, final int offset, final int length) {
    if (fillBuffer(src, offset, length)) {
      return;
    }
    processBuffer(false);
    if (fillBuffer(src, offset, length)) {
      return;
    }

    if (firstData) {
      if (initialArrayUpdater.isPresent()) {
        state = initialArrayUpdater.get().apply(src, offset, length);
      } else {
        state = stateSupplier.apply(state);
        arrayUpdater.accept(state, src, offset, length);
      }
    } else {
      arrayUpdater.accept(state, src, offset, length);
    }
    firstData = false;
  }

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

  public R doFinal() throws X {
    if (!firstData || !singlePassArray.isPresent()) {
      processBuffer(true);
      return finalHandler.apply(state);
    } else {
      return singlePassArray.get().apply(buff.getDataBuffer(), 0, buff.size());
    }
  }

  /**
   * WARNING! This only does a shallow copy of the handlers, so any which refer to external state
   * (so, any values not passed in as arguments) may be incorrect and need to be fixed prior to use.
   */
  @Override
  protected InputBuffer<R, S, X> clone() throws CloneNotSupportedException {
    if (state != null && !stateCloner.isPresent()) {
      throw new CloneNotSupportedException("No stateCloner configured");
    }
    @SuppressWarnings("unchecked")
    final InputBuffer<R, S, X> clonedObject = (InputBuffer<R, S, X>) super.clone();

    clonedObject.state = state != null ? stateCloner.get().apply(state) : null;
    clonedObject.buff = buff.clone();

    return clonedObject;
  }

  /**
   * An array view over a bytebuffer - either directly aliasing the underlying bytebuffer, or a copy
   * of the byte buffer's data.
   */
  private static class ShimArray {
    private final ByteBuffer backingBuffer;
    public final byte[] array;
    public final int offset, length;

    public ShimArray(final ByteBuffer buffer) {
      this.backingBuffer = buffer.slice();
      this.length = backingBuffer.limit();

      final boolean hasArray = backingBuffer.hasArray();
      byte[] tmpArray = hasArray ? backingBuffer.array() : null;
      if (tmpArray == null) {
        tmpArray = new byte[length];
        backingBuffer.duplicate().get(tmpArray);
        offset = 0;
      } else {
        offset = backingBuffer.arrayOffset() + backingBuffer.position();
      }

      this.array = tmpArray;
    }
  }
}
