package net.java.otr4j.io;

import org.bouncycastle.util.BigIntegers;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

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

    @Test(expected = NullPointerException.class)
    public void testWriteNullUserProfile() {
        final OtrOutputStream otr = new OtrOutputStream(out);
        otr.writeClientProfile(null);
    }

    @Test
    public void testCloseStream() {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeBigInt(BigInteger.ONE);
        }
    }

    @Test
    public void testProduceEmptyResult() {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            assertArrayEquals(new byte[0], out.toByteArray());
        }
    }

    @Test
    public void testProduceDataResult() {
        final byte[] data = new byte[20];
        RANDOM.nextBytes(data);
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeData(data);
            assertArrayEquals(concatenate(new byte[] {0, 0, 0, 20}, data), out.toByteArray());
        }
    }

    @Test
    public void testProduceBigIntResult() {
        final BigInteger value = new BigInteger("9876543211234567890");
        final byte[] expected = concatenate(new byte[] { 0, 0, 0, 8}, BigIntegers.asUnsignedByteArray(value));
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeBigInt(value);
            assertArrayEquals(expected, out.toByteArray());
        }
    }

    @Test
    public void testProduceShortResult() {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeShort(0xffff);
            assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff}, out.toByteArray());
        }
    }

    @Test
    public void testProduceShortResultOverflowing() {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeShort(0x0001ffff);
            assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff}, out.toByteArray());
        }
    }

    @Test
    public void testProduceIntResult() {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeInt(0xffffffff);
            assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}, out.toByteArray());
        }
    }

    @Test
    public void testProduceByteResult() {
        final byte value = (byte) 0xf5;
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeByte(value);
            assertArrayEquals(new byte[] {value}, out.toByteArray());
        }
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
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeLong(value);
            assertArrayEquals(expected, out.toByteArray());
        }
    }
}
