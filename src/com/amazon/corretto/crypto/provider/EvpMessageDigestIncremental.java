package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.ArrayList;
import java.util.Arrays;

public class EvpMessageDigestIncremental extends MessageDigestSpi implements Cloneable {
    private int hashSize;
    private int digestType;
    private Object turnstile;
    private final int BUFFER_SIZE = 1024;
    private byte[] buf = new byte[BUFFER_SIZE];
    private int pos = 0;
    private boolean needInitializeCtx = true;
    private long[] ctx;
    static native void singlePassDigest(int digestType, byte[] digest, byte[] buf, int offset, int bufLen);
    private native void initContext(int digestType, long[] ctxOut);
    private native void cloneContext(long ctxPtr, long[] ctxOut);
    private native void updateInputArray(long ctxPtr, byte[] data, int offset, int length);
    private native void updateInputBuffer(long ctxPtr, ByteBuffer b);
    private native void finish(long ctxPtr, byte[] digestOutput, int offset);
    private native void reset(long ctxPtr);

    static {
        Loader.checkNativeLibraryAvailability();
    }

    public EvpMessageDigestIncremental(int _digestType, int _hashSize)
    {
        Loader.checkNativeLibraryAvailability();
        hashSize = _hashSize;
        digestType = _digestType;
        turnstile = new Object();
        ctx = new long[1];
    }

    @Override
    protected void engineUpdate(byte b)
    {
        synchronized (turnstile) {
            if (needInitializeCtx) {
                initContext(digestType, ctx);
                needInitializeCtx = false;
            }
            byte[] a = new byte[1];
            a[0] = b;
            engineUpdate(a, 0, 1);
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length)
    {
        synchronized (turnstile)
        {
            if (needInitializeCtx) {
                initContext(digestType, ctx);
                needInitializeCtx = false;
            }
            if (pos + length <= BUFFER_SIZE)
            {
                System.arraycopy(input, offset, buf, pos, length);
                pos += length;
                return;
            } else {
                if (pos > 0) {
                    updateInputArray(ctx[0], buf, 0, pos);
                    pos = 0;
                    Arrays.fill(buf, (byte) 0);
                }
                if (length <= BUFFER_SIZE)
                {
                    System.arraycopy(input, offset, buf, 0, length);
                    pos = length;
                } else {
                    updateInputArray(ctx[0], input, offset, length);
                }
            }
        }
    }

    @Override
    protected void engineUpdate(ByteBuffer bb)
    {
        synchronized (turnstile) {
            if (needInitializeCtx) {
                initContext(digestType, ctx);
                needInitializeCtx = false;
            }
            if (pos > 0)
            {
                updateInputArray(ctx[0], buf, 0, pos);
                pos = 0;
                Arrays.fill(buf, (byte) 0);
            }
            if (bb.isDirect()) {
                updateInputBuffer(ctx[0], bb);
                bb.position(bb.limit());
            }
            else {
                int len = bb.remaining();
                byte[] a = new byte[len];
                bb.get(a);
                engineUpdate(a, 0, len);
            }
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
            EvpMessageDigestIncremental clonedObject = (EvpMessageDigestIncremental) super.clone();
            clonedObject.hashSize = hashSize;
            clonedObject.digestType = digestType;
            clonedObject.buf = buf.clone();
            clonedObject.pos = pos;
            clonedObject.turnstile = new Object();
            cloneContext(ctx[0], clonedObject.ctx);
            return clonedObject;
        }
        catch (CloneNotSupportedException e) {
            throw new Error("Unexpected CloneNotSupportedException", e);
        }
    }

    @Override
    protected byte[] engineDigest()
    {
        if (needInitializeCtx) {
            throw new IllegalArgumentException("never submitted input");
        }
        synchronized (turnstile) {
            if (pos > 0) {
                updateInputArray(ctx[0], buf, 0, pos);
                pos = 0;
                Arrays.fill(buf, (byte) 0);
            }
            int len = engineGetDigestLength();
            byte[] output = new byte[len];
            finish(ctx[0], output, 0);
            needInitializeCtx = true;
            ctx[0] = 0;
            return output;
        }
    }

    @Override
    protected int engineDigest(byte[] outputBuf, int offset, int len) throws DigestException
    {
        if (needInitializeCtx) {
            throw new IllegalArgumentException("never submitted input");
        }
        if (offset + len > outputBuf.length) {
            throw new IllegalArgumentException("Buffer length too small");
        }
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
        }
        reset(ctx[0]);

        return;
    }

    static class MD5 extends EvpMessageDigestIncremental
    {
        private static final int HASH_SIZE = 16;
        public MD5() {
            super(0, HASH_SIZE);
        }
    }
    static class SHA1 extends EvpMessageDigestIncremental
    {
        private static final int HASH_SIZE = 20;
        public SHA1() {
            super(1, HASH_SIZE);
        }
    }

    static class SHA256 extends EvpMessageDigestIncremental
    {
        private static final int HASH_SIZE = 32;
        public SHA256() {
            super(2, HASH_SIZE);
        }
    }

    static class SHA384 extends EvpMessageDigestIncremental
    {
        private static final int HASH_SIZE = 48;
        public SHA384() {
            super(3, HASH_SIZE);
        }
    }

    static class SHA512 extends EvpMessageDigestIncremental
    {
        private static final int HASH_SIZE = 64;
        public SHA512() {
            super(4, HASH_SIZE);
        }
    }
}

