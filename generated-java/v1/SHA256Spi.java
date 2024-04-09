package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;

public final class SHA256Spi extends MessageDigestSpi implements Cloneable {
    private static final int HASH_SIZE = 32;
    private static final long[] CONTEXT;

    private InputBuffer<byte[], long[], RuntimeException> buffer;

    static {
        Loader.checkNativeLibraryAvailability();
        CONTEXT = new long[1];
        initContext(CONTEXT);
    }

    public SHA256Spi()
    {
        Loader.checkNativeLibraryAvailability();

        this.buffer = new InputBuffer<byte[], long[], RuntimeException>(1024)
                .withInitialStateSupplier(SHA256Spi::resetContext)
                .withUpdater(SHA256Spi::synchronizedUpdateContextByteArray)
                .withUpdater(SHA256Spi::synchronizedUpdateNativeByteBuffer)
                .withDoFinal(SHA256Spi::doFinal)
                .withSinglePass(SHA256Spi::singlePass)
                .withStateCloner((context) -> context.clone());
    }

    static native void fastDigest(byte[] digest, byte[] buf, int offset, int bufLen);

    private static native void initContext(long[] context);

    private static native void updateContextByteArray(long context, byte[] buf, int offset, int length);

    private static void synchronizedUpdateContextByteArray(long[] context, byte[] buf, int offset, int length)
    {
        synchronized (context)
        {
            updateContextByteArray(context[0], buf, offset, length);
        }
    }

    private static native void updateNativeByteBuffer(long context, ByteBuffer buf);

    private static void synchronizedUpdateNativeByteBuffer(long[] context, ByteBuffer buf)
    {
        synchronized (context)
        {
            updateNativeByteBuffer(context[0], buf);
        }
    }

    private static native void finish(long context, byte[] digest, int offset);

    private static void synchronizedFinish(long[] context, byte[] digest, int offset)
    {
        synchronized (context)
        {
            finish(context[0], digest, offset);
        }
    }

    private static long[] resetContext(long[] context)
    {
        if (context == null)
        {
            context = CONTEXT.clone();
        }
        else
        {
            context[0] = CONTEXT[0];
        }
        return context;
    }

    private static byte[] doFinal(long[] context)
    {
        final byte[] result = new byte[HASH_SIZE];
        synchronizedFinish(context, result, 0);
        return result;
    }

    private static byte[] singlePass(byte[] src, int offset, int length)
    {
        /*
        if (offset != 0 || length != src.length)
        {
            src = Arrays.copyOf(src, length);  // if offset is not 0, why do I copy from src[0]?
            // Why do I even need this copy? I can just pass the array down to JNI along with
            // offset and length, have JNI take the appropriate range out of it
            offset = 0;
        }
        */

        final byte[] result = new byte[HASH_SIZE];
        fastDigest(result, src, offset, /*src.length*/ length);
        return result;
    }

    @Override
    protected void engineUpdate(byte input)
    {
        buffer.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length)
    {
        buffer.update(input, offset, length);
    }

    @Override
    protected void engineUpdate(ByteBuffer buf)
    {
        buffer.update(buf);
    }

    @Override
    protected int engineGetDigestLength()
    {
        return HASH_SIZE;
    }

    @Override
    public Object clone()
    {
        try
        {
            SHA256Spi clonedObject = (SHA256Spi) super.clone();
            clonedObject.buffer = buffer.clone();
            return clonedObject;
        }
        catch (CloneNotSupportedException e)
        {
            throw new Error("Unexpected CloneNotSupportedException", e);
        }
    }

    @Override
    protected byte[] engineDigest()
    {
        try {
            return buffer.doFinal();
        }
        finally {
            engineReset();
        }
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException
    {
        if (len < HASH_SIZE)
            throw new IllegalArgumentException("Buffer length too small");

        final byte[] digest = engineDigest();

        try {
            System.arraycopy(digest, 0, buf, offset, HASH_SIZE);
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException(e);
        }
        return HASH_SIZE;
    }

    @Override
    protected void engineReset()
    {
        buffer.reset();
    }
}