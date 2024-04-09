package com.amazon.corretto.crypto.provider;

import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

import static java.util.logging.Logger.getLogger;

public class EvpHmacSinglePass extends MacSpi implements Cloneable {
    private int macSize;
    private int digestType;
    private SecretKey key;
    private byte[] encoded_key;
    private Object turnstile;
    private final int BUFFER_SIZE = 1024;
    private byte[] buf = new byte[BUFFER_SIZE];
    private int pos = 0;
    private ArrayList<Byte> bigBuf;

    static native void singlePassHmac(int digestType, byte[] output, byte[] key,  byte[] input_buf, int input_offset, int input_len);

    static {
        Loader.checkNativeLibraryAvailability();
    }

    public EvpHmacSinglePass(int _digestType, int _macSize) {
        Loader.checkNativeLibraryAvailability();
        digestType = _digestType;
        macSize = _macSize;
        turnstile = new Object();
    }

    public void setKey(SecretKey _key) throws InvalidKeyException {
        if (Objects.equals(this.key, _key)) {
            return;
        }

        if (!"RAW".equalsIgnoreCase(_key.getFormat())) {
            throw new InvalidKeyException("key must support RAW encoding");
        }

        byte[] encoded = _key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key encoding must not be null");
        }

        this.encoded_key = encoded;
        this.key = _key;
    }

    @Override
    protected int engineGetMacLength() {
        return macSize;
    }

    @Override
    protected void engineInit(Key _key, AlgorithmParameterSpec _params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (_params != null) {
            throw new InvalidAlgorithmParameterException("Params must be null");
        }
        if (!(_key instanceof  SecretKey)) {
            throw new InvalidKeyException("Hmac uses expects a SecretKey");
        }
        setKey((SecretKey)_key);
        engineReset();
    }

    @Override
    protected void engineUpdate(byte b) {
        synchronized (turnstile) {
            if (pos >= 0) {
                if (pos + 1 <= BUFFER_SIZE) {
                    buf[pos] = b;
                    pos++;
                    return;
                } else {
                    bigBuf = new ArrayList<>(BUFFER_SIZE + 1);
                    for (byte i : buf)
                        bigBuf.add(i);
                    bigBuf.add(b);
                    Arrays.fill(buf, (byte) 0);
                    pos = -1;
                }
            } else {
                bigBuf.add(b);
            }
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        synchronized (turnstile) {
            if (pos >= 0) {
                if (pos + length <= BUFFER_SIZE) {
                    System.arraycopy(input, offset, buf, pos, length);
                    pos += length;
                    return;
                } else {
                    bigBuf = new ArrayList<>(pos + length);
                    for (int i = 0; i < pos; i++)
                        bigBuf.add(buf[i]);
                    for (int i = offset; i < offset + length; i++)
                        bigBuf.add(input[i]);
                    Arrays.fill(buf, (byte) 0);
                    pos = -1;
                }
            } else {
                for (int i = offset; i < offset + length; i++)
                    bigBuf.add(input[i]);
            }
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        synchronized (turnstile) {
            byte[] output = new byte[macSize];
            if (pos >= 0) {
                singlePassHmac(digestType, output, encoded_key, buf, 0, pos);
            } else {
                int len = bigBuf.size();
                byte[] a = new byte[len];
                for (int i = 0; i < len; i++)
                    a[i] = bigBuf.get(i);
                singlePassHmac(digestType, output, encoded_key, a, 0, len);
            }
            Arrays.fill(buf, (byte)0);
            pos = 0;
            bigBuf = null;
            return output;
        }
    }

    @Override
    protected void engineReset() {
        Arrays.fill(buf, (byte) 0);
        pos = 0;
        if (pos < 0) {
            bigBuf = null;
        }
    }

    private void assertKeyProvided() {
        if (key == null)
            throw new IllegalStateException("HMAC key not provided");
    }

    @Override
    public EvpHmacSinglePass clone() throws CloneNotSupportedException {
        EvpHmacSinglePass cloned = (EvpHmacSinglePass) super.clone();
        cloned.digestType = digestType;
        cloned.macSize = macSize;
        cloned.buf = buf.clone();
        cloned.pos = pos;
        try {
            cloned.setKey(key);
        } catch (InvalidKeyException e) {
            throw new CloneNotSupportedException();
        }
        if (encoded_key != null)
            cloned.encoded_key = encoded_key.clone();
        cloned.turnstile = new Object();
        if (bigBuf != null)
            cloned.bigBuf = (ArrayList)bigBuf.clone();
        return cloned;
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

    static class SHA1 extends EvpHmacSinglePass {
        private static final int digestType = 1;
        private static final int digestLength = 20;
        static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest("HmacSHA1", SHA1::runSelfTest);
        public SHA1() {
            super(digestType, digestLength);
        }
        public static SelfTestResult runSelfTest() {
            return EvpHmacSinglePass.runSelfTest("HmacSHA1", SHA1.class);
        }
    }
    static class SHA256 extends EvpHmacSinglePass {
        private static final int digestType = 2;
        private static final int digestLength = 32;
        static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest("HmacSHA256", SHA1::runSelfTest);
        public SHA256() {
            super(digestType, digestLength);
        }
        public static SelfTestResult runSelfTest() {
            return EvpHmacSinglePass.runSelfTest("HmacSHA256", SHA256.class);
        }
    }

    static class SHA384 extends EvpHmacSinglePass {
        private static final int digestType = 3;
        private static final int digestLength = 48;
        static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest("HmacSHA384", SHA384::runSelfTest);
        public SHA384() {
            super(digestType, digestLength);
        }
        public static SelfTestResult runSelfTest() {
            return EvpHmacSinglePass.runSelfTest("HmacSHA384", SHA384.class);
        }
    }

    static class SHA512 extends EvpHmacSinglePass {
        private static final int digestType = 4;
        private static final int digestLength = 64;
        static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest("HmacSHA512", SHA512::runSelfTest);
        public SHA512() {
            super(digestType, digestLength);
        }
        public static SelfTestResult runSelfTest() {
            return EvpHmacSinglePass.runSelfTest("HmacSHA512", SHA512.class);
        }
    }
}

