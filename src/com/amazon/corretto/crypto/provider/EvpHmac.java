// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static java.util.logging.Logger.getLogger;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class EvpHmac extends MacSpi implements Cloneable {

  private static final int NEED_COMPLETE_REINITIALIZE = 0;
  private static final int RESET_INPUT_KEEP_KEY_AND_MD = 1;

  private static final int CONTINUOUS_UPDATE = 2;

  /* Returns the size of the array needed to hold the entire HMAC context. */
  //private static native int getContextSize();

  /**
   * Calls {@code EVP_MAC_Update} with {@code input}, possibly calling {@code EVP_MAC_Init} first (if
   * {@code instruction} is any value except {@link #CONTINUOUS_UPDATE}). This method should only be used via
   * {@link #synchronizedUpdateCtxArray(long, long[], int, int, byte[], byte[], int, int)}.
   *
   * @param ctx opaque pointer to an EVP_MAC_CTX
   */
  private static native void updateCtxArray(
      long ctx,
      long[] ctxOut,
      int instruction,
      int digestCode,
      byte[] key,
      byte[] input,
      int offset,
      int length);
  /**
   * @see #updateCtxArray(long, long[], int, int, byte[], byte[], int, int)
   */
  private static void synchronizedUpdateCtxArray(
          long ctx,
          long[] ctxOut,
          int instruction,
          int digestCode,
          byte[] key,
          byte[] input,
          int offset,
          int length)
  {
    synchronized (ctxOut) {
      updateCtxArray(ctx, ctxOut, instruction, digestCode, key, input, offset, length);
    }
  }

  /**
   * Calls {@code EVP_MAC_Final}, and places the result in {@code result}. This method should only be
   * called via {@link #synchronizedDoFinal(long[], byte[])}
   *
   * @param ctx opaque array containing native context
   * @param result output array
   */
  private static native void doFinal(long ctx, byte[] result);
  /**
   * @see #doFinal(long, byte[])
   */
  private static void synchronizedDoFinal(long[] ctx, byte[] result) {
    synchronized (ctx) {
      doFinal(ctx[0], result);
    }
  }

  /**
   * Calls {@code EVP_MAC_Init}, {@code EVP_MAC_Update}, and {@code EVP_MAC_Final} with {@code input}.
   * This method should only be used via {@link #synchronizedFastHmac(long, long[], int, int, byte[], byte[], int, int, byte[])}.
   *
   * @param ctx opaque array containing native context
   */
  private static native void fastHmac(
      long ctx,
      long[] ctxOut,
      int instruction,
      int digestCode,
      byte[] key,
      byte[] input,
      int offset,
      int length,
      byte[] result);
  /**
   * @see #fastHmac(long, long[], int, int, byte[], byte[], int, int, byte[])
   */
  private static void synchronizedFastHmac(
          long ctx,
          long[] ctxOut,
          int instruction,
          int digestCode,
          byte[] key,
          byte[] input,
          int offset,
          int length,
          byte[] result)
  {
    synchronized (ctxOut) {
      fastHmac(ctx, ctxOut, instruction, digestCode, key, input, offset, length, result);
    }
  }

  // These must be explicitly cloned
  private HmacState state;
  private InputBuffer<byte[], Void, RuntimeException> buffer;

  EvpHmac(int digestCode, int digestLength) {
    this.state = new HmacState(digestCode, digestLength);
    this.buffer = new InputBuffer<>(1024);
    configureLambdas();
  }

  private void configureLambdas() {
    buffer
        .withInitialUpdater(
            (src, offset, length) -> {
              assertKeyProvided();
              byte[] rawKey = state.encoded_key;
              int instruction;
              if (state.needsRekey) {
                instruction = NEED_COMPLETE_REINITIALIZE;
              }
              else {
                instruction = RESET_INPUT_KEEP_KEY_AND_MD;
              }
              synchronizedUpdateCtxArray(state.ctx[0], state.ctx, instruction, state.digestCode, rawKey, src, offset, length);
              state.needsRekey = false;
              return null;
            })
        .withUpdater(
            (ignored, src, offset, length) -> {
              assertKeyProvided();
              synchronizedUpdateCtxArray(state.ctx[0], state.ctx, CONTINUOUS_UPDATE, state.digestCode, null, src, offset, length);
            })
        .withDoFinal(
            (ignored) -> {
              assertKeyProvided();
              final byte[] result = new byte[state.digestLength];
              synchronizedDoFinal(state.ctx, result);
              return result;
            })
        .withSinglePass(
            (src, offset, length) -> {
              assertKeyProvided();
              final byte[] result = new byte[state.digestLength];
              byte[] rawKey = state.encoded_key;
              int instruction;
              if (state.needsRekey) {
                instruction = NEED_COMPLETE_REINITIALIZE;
              }
              else {
                instruction = RESET_INPUT_KEEP_KEY_AND_MD;
              }
              synchronizedFastHmac(state.ctx[0], state.ctx, instruction, state.digestCode, rawKey, src, offset, length, result);
              state.needsRekey = false;
              return result;
            });
  }

  @Override
  protected int engineGetMacLength() {
    return state.digestLength;
  }

  @Override
  protected void engineInit(Key key, AlgorithmParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params != null) {
      throw new InvalidAlgorithmParameterException("Params must be null");
    }
    if (!(key instanceof SecretKey)) {
      throw new InvalidKeyException("Hmac uses expects a SecretKey");
    }
    state.setKey((SecretKey) key);
    engineReset();
  }

  @Override
  protected void engineUpdate(byte input) {
    buffer.update(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    buffer.update(input, offset, len);
  }

  @Override
  protected byte[] engineDoFinal() {
    return buffer.doFinal();
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  private void assertKeyProvided() {
    if (state.key == null) {
      throw new IllegalStateException("HMAC key not provided");
    }
  }

  @Override
  public EvpHmac clone() throws CloneNotSupportedException {
    EvpHmac cloned = (EvpHmac) super.clone();
    cloned.state = cloned.state.clone();
    cloned.buffer = cloned.buffer.clone();
    cloned.configureLambdas();
    return cloned;
  }

  private static final class HmacState implements Cloneable {
    private SecretKey key;
    private final int digestCode;
    public long[] ctx;
    private final int digestLength;
    private byte[] encoded_key;
    boolean needsRekey = true;

    private HmacState(int digestCode, int digestLength) {
      this.digestCode = digestCode;
      this.digestLength = digestLength;
      ctx = new long[1];
    }

    private void setKey(SecretKey key) throws InvalidKeyException {
      if (Objects.equals(this.key, key)) {
        return;
      }
      // Check new key for usability
      if (!"RAW".equalsIgnoreCase(key.getFormat())) {
        throw new InvalidKeyException("Key must support RAW encoding");
      }
      byte[] encoded = key.getEncoded();
      if (encoded == null) {
        throw new InvalidKeyException("Key encoding must not be null");
      }
      this.encoded_key = encoded;
      this.key = key;
      this.needsRekey = true;
    }

    @Override
    public HmacState clone() {
      try {
        HmacState cl = (HmacState) super.clone();
        cl.ctx = ctx.clone();  // Do I need this? encoded_key is an array, but it's not separately cloned.
        return cl;
      } catch (final CloneNotSupportedException ex) {
        throw new AssertionError(ex);
      }
    }
  }

  @SuppressWarnings("serial")
  private static class TestMacProvider extends Provider {
    private final String macName;
    private final Class<? extends MacSpi> spi;
    // The super constructor taking a double version is deprecated in java 9.
    // However, the replacement for it is
    // unavailable in java 8, so to build on both with warnings on our only choice
    // is suppressing deprecation warnings.
    @SuppressWarnings({"deprecation"})
    protected TestMacProvider(String macName, Class<? extends MacSpi> spi) {
      super("test provider", 0, "internal self-test provider for " + macName);
      this.macName = macName;
      this.spi = spi;
    }

    @Override
    public synchronized Service getService(final String type, final String algorithm) {
      if (type.equals("Mac") && algorithm.equals(macName)) {
        return new Service(
            this, type, algorithm, spi.getName(), Collections.emptyList(), Collections.emptyMap()) {
          @Override
          public Object newInstance(final Object constructorParameter) {
            try {
              return spi.getConstructor().newInstance();
            } catch (final Exception ex) {
              throw new AssertionError(ex);
            }
          }
        };
      } else {
        return super.getService(type, algorithm);
      }
    }
  }

  private static SelfTestResult runSelfTest(String macName, Class<? extends MacSpi> spi) {
    Provider p = new TestMacProvider(macName, spi);

    int tests = 0;
    final Map<String, String> hashCategory = new HashMap<>();
    final Map<String, Integer> hashLocation = new HashMap<>();
    hashCategory.put("HmacMD5", "md5");
    hashLocation.put("HmacMD5", 0);
    hashCategory.put("HmacSHA1", "sha1");
    hashLocation.put("HmacSHA1", 0);
    hashCategory.put("HmacSHA256", "sha2");
    hashLocation.put("HmacSHA256", 0);
    hashCategory.put("HmacSHA384", "sha2");
    hashLocation.put("HmacSHA384", 1);
    hashCategory.put("HmacSHA512", "sha2");
    hashLocation.put("HmacSHA512", 2);

    try (final Scanner in =
        new Scanner(Loader.getTestData("hmac.txt"), StandardCharsets.US_ASCII.name())) {
      final Mac testMac = Mac.getInstance(macName, p);
      while (in.hasNext()) {
        tests++;
        final String type = in.next();
        SecretKey key = new SecretKeySpec(Utils.decodeHex(in.next()), macName);
        byte[] message = Utils.decodeHex(in.next());
        String[] expecteds = in.nextLine().trim().split("\\s+");
        if (type.equals(hashCategory.get(macName))) {
          Utils.testMac(
              testMac, key, message, Utils.decodeHex(expecteds[hashLocation.get(macName)]));
        }
      }
      return new SelfTestResult(SelfTestStatus.PASSED);
    } catch (Throwable ex) {
      getLogger("AmazonCorrettoCryptoProvider").severe(macName + " failed self-test " + tests);
      return new SelfTestResult(ex);
    }
  }

  static class MD5 extends EvpHmac {
    //private static final long evpMd = Utils.getEvpMdFromName("md5");
    //private static final int digestLength = Utils.getDigestLength(evpMd);
    private static final int digestCode = 0;
    private static final int digestLength = 16;
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacMD5", MD5::runSelfTest);

    public MD5() {
      super(digestCode, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacMD5", MD5.class);
    }
  }

  static class SHA1 extends EvpHmac {
    //private static final long evpMd = Utils.getEvpMdFromName("sha1");
    //private static final int digestLength = Utils.getDigestLength(evpMd);
    private static final int digestCode = 1;
    private static final int digestLength = 20;
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA1", SHA1::runSelfTest);

    public SHA1() {
      super(digestCode, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA1", SHA1.class);
    }
  }

  static class SHA256 extends EvpHmac {
    //private static final long evpMd = Utils.getEvpMdFromName("sha256");
    //private static final int digestLength = Utils.getDigestLength(evpMd);
    private static final int digestCode = 2;
    private static final int digestLength = 32;
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA256", SHA256::runSelfTest);

    public SHA256() {
      super(digestCode, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA256", SHA256.class);
    }
  }

  static class SHA384 extends EvpHmac {
    //private static final long evpMd = Utils.getEvpMdFromName("sha384");
    //private static final int digestLength = Utils.getDigestLength(evpMd);
    private static final int digestCode = 3;
    private static final int digestLength = 48;
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA384", SHA384::runSelfTest);

    public SHA384() {
      super(digestCode, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA384", SHA384.class);
    }
  }

  static class SHA512 extends EvpHmac {
    //private static final long evpMd = Utils.getEvpMdFromName("sha512");
    //private static final int digestLength = Utils.getDigestLength(evpMd);
    private static final int digestCode = 4;
    private static final int digestLength = 64;
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA512", SHA512::runSelfTest);

    public SHA512() {
      super(digestCode, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA512", SHA512.class);
    }
  }
}
