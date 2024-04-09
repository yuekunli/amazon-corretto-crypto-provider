package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.ArrayList;
import java.util.Arrays;

public class EvpMessageDigest extends MessageDigestSpi implements Cloneable {
    private int hashSize;
    private int digestType;
    private Object turnstile;
    private final int BUFFER_SIZE = 1024;
    private byte[] buf = new byte[BUFFER_SIZE];

    private int pos = 0;

    private ArrayList<Byte> bigBuf;

    static native void singlePassDigest(int digestType, byte[] digest, byte[] buf, int offset, int bufLen);

    static {
        Loader.checkNativeLibraryAvailability();
    }

    public EvpMessageDigest(int _digestType, int _hashSize)
    {
        Loader.checkNativeLibraryAvailability();
        hashSize = _hashSize;
        digestType = _digestType;
        turnstile = new Object();
    }

    @Override
    protected void engineUpdate(byte b)
    {
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
    protected void engineUpdate(byte[] input, int offset, int length)
    {
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
    protected void engineUpdate(ByteBuffer buf)
    {
        synchronized (turnstile) {
            int len = buf.remaining();
            byte[] a = new byte[len];
            buf.get(a);
            engineUpdate(a, 0, len);
        }
    }

    @Override
    protected int engineGetDigestLength()
    {
        return hashSize;
    }

    @Override
    public Object clone()
    {
        try
        {
           EvpMessageDigest clonedObject = (EvpMessageDigest) super.clone();
           clonedObject.hashSize = hashSize;
           clonedObject.digestType = digestType;
           clonedObject.buf = buf.clone();
           clonedObject.pos = pos;
           clonedObject.turnstile = new Object();
           if (bigBuf != null)
               clonedObject.bigBuf = (ArrayList)bigBuf.clone();
           return clonedObject;
        }
        catch (CloneNotSupportedException e) {
            throw new Error("Unexpected CloneNotSupportedException", e);
        }
    }

    @Override
    protected byte[] engineDigest()
    {
        synchronized (turnstile) {
            byte[] output = new byte[hashSize];
            if (pos >= 0) {
                singlePassDigest(digestType, output, buf, 0, pos);
            } else {
                int len = bigBuf.size();
                byte[] a = new byte[len];
                for (int i = 0; i < len; i++)
                    a[i] = bigBuf.get(i);
                singlePassDigest(digestType, output, a, 0, len);
            }
            Arrays.fill(buf, (byte) 0);
            pos = 0;
            bigBuf = null;
            return output;
        }
    }

    @Override
    protected int engineDigest(byte[] outputBuf, int offset, int len) throws DigestException
    {
        if (len < hashSize)
            throw new IllegalArgumentException("Buffer length too small");

        final byte[] result = engineDigest();

        try {
            System.arraycopy(result, 0, outputBuf, offset, hashSize);
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException(e);
        }
        return hashSize;
    }

    @Override
    protected void engineReset()
    {
        if (pos >= 0) {
            Arrays.fill(buf, (byte)0);
            pos = 0;
        } else {
            Arrays.fill(buf, (byte)0);
            pos = 0;
            bigBuf = null;
        }
        return;
    }

    static class MD5 extends EvpMessageDigest
    {
        private static final int HASH_SIZE = 16;
        public MD5() {
            super(0, HASH_SIZE);
        }
    }
    static class SHA1 extends EvpMessageDigest
    {
        private static final int HASH_SIZE = 20;
        public SHA1() {
            super(1, HASH_SIZE);
        }
    }

    static class SHA256 extends EvpMessageDigest
    {
        private static final int HASH_SIZE = 32;
        public SHA256() {
            super(2, HASH_SIZE);
        }
    }

    static class SHA384 extends EvpMessageDigest
    {
        private static final int HASH_SIZE = 48;
        public SHA384() {
            super(3, HASH_SIZE);
        }
    }

    static class SHA512 extends EvpMessageDigest
    {
        private static final int HASH_SIZE = 64;
        public SHA512() {
            super(4, HASH_SIZE);
        }
    }
}
