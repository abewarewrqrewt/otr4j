package net.java.otr4j.io;

import org.bouncycastle.util.BigIntegers;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.assertArrayEquals;

@SuppressWarnings("ConstantConditions")
public class OtrOutputStreamTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final ByteArrayOutputStream out = new ByteArrayOutputStream();

    @Test
    public void testConstruction() {
        new OtrOutputStream();
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullOutputStream() {
        new OtrOutputStream(null);
    }

    @Test
    public void testConstructOtrOutputStream() {
        new OtrOutputStream(out);
    }

    @Test
    public void testProduceEmptyResult() {
        assertArrayEquals(new byte[0], new OtrOutputStream().toByteArray());
    }

    @Test
    public void testProduceDataResult() {
        final byte[] data = new byte[20];
        RANDOM.nextBytes(data);
        assertArrayEquals(concatenate(new byte[]{0, 0, 0, 20}, data),
            new OtrOutputStream().writeData(data).toByteArray());
    }

    @Test
    public void testProduceBigIntResult() {
        final BigInteger value = new BigInteger("9876543211234567890");
        final byte[] expected = concatenate(new byte[] { 0, 0, 0, 8}, BigIntegers.asUnsignedByteArray(value));
        assertArrayEquals(expected, new OtrOutputStream().writeBigInt(value).toByteArray());
    }

    @Test
    public void testProduceShortResult() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff},
            new OtrOutputStream().writeShort(0xffff).toByteArray());
    }

    @Test
    public void testProduceShortResultOverflowing() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff},
            new OtrOutputStream().writeShort(0x0001ffff).toByteArray());
    }

    @Test
    public void testProduceIntResult() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new OtrOutputStream().writeInt(0xffffffff).toByteArray());
    }

    @Test
    public void testProduceByteResult() {
        final byte value = (byte) 0xf5;
        assertArrayEquals(new byte[] {value}, new OtrOutputStream().writeByte(value).toByteArray());
    }

    @Test
    public void testProduceLongResult() {
        final long value = RANDOM.nextLong();
        final byte[] expected = new byte[]{
            (byte) ((value & 0xff00000000000000L) >>> 56),
            (byte) ((value & 0xff000000000000L) >>> 48),
            (byte) ((value & 0xff0000000000L) >>> 40),
            (byte) ((value & 0xff00000000L) >>> 32),
            (byte) ((value & 0xff000000L) >>> 24),
            (byte) ((value & 0xff0000L) >>> 16),
            (byte) ((value & 0xff00L) >>> 8),
            (byte) (value & 0xffL)};
        assertArrayEquals(expected, new OtrOutputStream().writeLong(value).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteEncodableNull() {
        new OtrOutputStream().write(null);
    }

    @Test
    public void testWriteEncodable() {
        final byte[] data = "Hello world!".getBytes(UTF_8);
        final byte[] expected = concatenate(new byte[]{0, 0, 0, 0xc}, data);
        final byte[] result = new OtrOutputStream().write(new OtrEncodable() {
            @Override
            public void writeTo(@Nonnull final OtrOutputStream out) {
                out.writeData(data);
            }
        }).toByteArray();
        assertArrayEquals(expected, result);
    }
}
