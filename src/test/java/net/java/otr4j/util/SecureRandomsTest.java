/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.util;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class SecureRandomsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testRandomNullSecureRandom() {
        randomBytes(null, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testRandomNullDestination() {
        randomBytes(RANDOM, null);
    }

    @Test
    public void testRandom() {
        assertFalse(allZeroBytes(randomBytes(RANDOM, new byte[100])));
    }

    @Test
    public void testRandomReturnsSameInstance() {
        final byte[] data = new byte[1];
        assertSame(data, randomBytes(RANDOM, data));
    }

    @Test
    public void testRandomAcceptsZeroLengthArray() {
        final byte[] data = new byte[0];
        assertSame(data, randomBytes(RANDOM, data));
    }

    @Test
    public void testRandomBehavesExpectedly() {
        final byte[] rand1 = randomBytes(RANDOM, new byte[24]);
        final byte[] rand2 = randomBytes(RANDOM, new byte[24]);
        final byte[] rand3 = randomBytes(RANDOM, new byte[24]);
        final byte[] rand4 = randomBytes(RANDOM, new byte[24]);
        assertFalse(Arrays.equals(rand1, rand2));
        assertFalse(Arrays.equals(rand1, rand3));
        assertFalse(Arrays.equals(rand1, rand4));
        assertFalse(Arrays.equals(rand2, rand3));
        assertFalse(Arrays.equals(rand2, rand4));
        assertFalse(Arrays.equals(rand3, rand4));
    }
}
