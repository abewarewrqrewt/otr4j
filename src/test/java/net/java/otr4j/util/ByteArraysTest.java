package net.java.otr4j.util;

import org.junit.Test;

import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.fromHexString;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.ByteArrays.toHexString;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
public class ByteArraysTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testRequireLengthExactlyNullArray() {
        requireLengthExactly(0, null);
    }

    @Test
    public void testRequireLengthExactlyCorrect() {
        final byte[] t = new byte[22];
        assertSame(t, requireLengthExactly(22, t));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireLengthExactlyOffByOneDown() {
        final byte[] t = new byte[22];
        requireLengthExactly(23, t);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireLengthExactlyOffByOneUp() {
        final byte[] t = new byte[22];
        requireLengthExactly(21, t);
    }

    @Test
    public void testAllZeroBytes() {
        assertTrue(allZeroBytes(new byte[300]));
    }

    @Test
    public void testAllZeroEmptyByteArray() {
        assertTrue(allZeroBytes(new byte[0]));
    }

    @Test(expected = NullPointerException.class)
    public void testAllZeroNullByteArray() {
        allZeroBytes(null);
    }

    @Test
    public void testAllZeroNonzeroBytes() {
        final byte[] data = new byte[20];
        data[RANDOM.nextInt(20)] = 1;
        assertFalse(allZeroBytes(data));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCompareSameStringConstantTime() {
        final byte[] data = new byte[200];
        RANDOM.nextBytes(data);
        constantTimeEquals(data, data);
    }

    @Test
    public void testCompareEqualSizeBytesUnequal() {
        final byte[] data1 = new byte[200];
        final byte[] data2 = new byte[200];
        RANDOM.nextBytes(data1);
        RANDOM.nextBytes(data2);
        data2[0] = (byte) (data1[0] ^ 0x1);
        assertFalse(constantTimeEquals(data1, data2));
    }

    @Test
    public void testCompareEqualSizeBytes() {
        final byte[] data1 = new byte[200];
        RANDOM.nextBytes(data1);
        final byte[] data2 = new byte[200];
        System.arraycopy(data1, 0, data2, 0, data1.length);
        assertTrue(constantTimeEquals(data1, data2));
    }

    @Test
    public void testCompareUnequalSizeBytes() {
        final byte[] data1 = new byte[200];
        final byte[] data2 = new byte[201];
        assertFalse(constantTimeEquals(data1, data2));
    }

    @Test(expected = NullPointerException.class)
    public void testCompareNullData1() {
        final byte[] data2 = new byte[200];
        constantTimeEquals(null, data2);
    }

    @Test(expected = NullPointerException.class)
    public void testCompareNullData2() {
        final byte[] data1 = new byte[200];
        constantTimeEquals(data1, null);
    }

    @Test(expected = NullPointerException.class)
    public void testCompareNullWithNull() {
        constantTimeEquals(null, null);
    }

    @Test(expected = NullPointerException.class)
    public void testByteArrayToHexStringNullArray() {
        toHexString(null);
    }

    @Test
    public void testByteArrayToHexStringEmptyArray() {
        assertEquals("", toHexString(new byte[0]));
    }

    @Test
    public void testByteArrayToHexStringSmallArray() {
        assertEquals("616230212F", toHexString(new byte[] { 'a', 'b', '0', '!', '/'}));
    }

    @Test
    public void testByteArrayToHexStringAndBack() {
        final byte[] line = "This is a line of text for testing out methods used for byte array to hex string conversions.".getBytes(UTF_8);
        assertArrayEquals(line, fromHexString(toHexString(line)));
    }
}
