/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.crypto.ed448.Scalars.one;
import static net.java.otr4j.crypto.ed448.Scalars.zero;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class ScalarsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testZero() {
        final Scalar zero = zero();
        assertTrue(allZeroBytes(zero.encode()));
    }

    @Test
    public void testZeroImmutableOverEncoding() {
        final Scalar zero = zero();
        final byte[] encoded = zero.encode();
        RANDOM.nextBytes(encoded);
        assertFalse(Arrays.equals(zero.encode(), encoded));
    }

    @Test
    public void testZeroImmutableOverInstances() {
        final Scalar zero1 = zero();
        final Scalar zero2 = zero();
        zero1.close();
        assertEquals(zero(), zero2.add(zero2));
    }

    @Test
    public void testOne() {
        final Scalar one = one();
        final byte[] oneBytes = one.encode();
        assertEquals(1, oneBytes[0]);
        for (int i = 1; i < oneBytes.length; i++) {
            assertEquals(0, oneBytes[i]);
        }
    }

    @Test
    public void testOneImmutableOverEncoding() {
        final Scalar one = one();
        final byte[] encoded = one.encode();
        RANDOM.nextBytes(encoded);
        assertFalse(Arrays.equals(one.encode(), encoded));
    }

    @Test
    public void testOneImmutableOverInstances() {
        final Scalar one1 = one();
        final Scalar one2 = one();
        one1.close();
        assertEquals(one(), one2.add(zero()));
    }
}