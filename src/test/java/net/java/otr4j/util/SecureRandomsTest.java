package net.java.otr4j.util;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.random;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class SecureRandomsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testRandomNullSecureRandom() {
        random(null, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testRandomNullDestination() {
        random(RANDOM, null);
    }

    @Test
    public void testRandom() {
        assertFalse(allZeroBytes(random(RANDOM, new byte[100])));
    }

    @Test
    public void testRandomReturnsSameInstance() {
        final byte[] data = new byte[1];
        assertSame(data, random(RANDOM, data));
    }

    @Test
    public void testRandomAcceptsZeroLengthArray() {
        final byte[] data = new byte[0];
        assertSame(data, random(RANDOM, data));
    }

    @Test
    public void testRandomBehavesExpectedly() {
        final byte[] rand1 = random(RANDOM, new byte[24]);
        final byte[] rand2 = random(RANDOM, new byte[24]);
        final byte[] rand3 = random(RANDOM, new byte[24]);
        final byte[] rand4 = random(RANDOM, new byte[24]);
        assertFalse(Arrays.equals(rand1, rand2));
        assertFalse(Arrays.equals(rand1, rand3));
        assertFalse(Arrays.equals(rand1, rand4));
        assertFalse(Arrays.equals(rand2, rand3));
        assertFalse(Arrays.equals(rand2, rand4));
        assertFalse(Arrays.equals(rand3, rand4));
    }
}
