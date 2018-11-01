/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import org.junit.Test;

import static net.java.otr4j.crypto.OtrCryptoEngine.checkEquals;

/**
 * Tests for OtrCryptoEngine.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class OtrCryptoEngineTest {

    @Test
    public void testCheckEqualsEqualArrays() throws OtrCryptoException {
        final byte[] a = new byte[]{'a','b','c','d','e'};
        final byte[] b = new byte[]{'a','b','c','d','e'};
        checkEquals(a, b, "Expected array to be equal.");
        checkEquals(b, a, "Expected array to be equal.");
    }

    @Test(expected = OtrCryptoException.class)
    public void testCheckEqualsArrayLengthDiff1() throws OtrCryptoException {
        final byte[] a = new byte[]{'a', 'a', 'a'};
        final byte[] b = new byte[]{'a', 'a', 'a', 'a'};
        checkEquals(a, b, "Expected array to be equal.");
    }

    @Test(expected = OtrCryptoException.class)
    public void testCheckEqualsArrayLengthDiff2() throws OtrCryptoException {
        final byte[] a = new byte[]{'a', 'a', 'a', 'a'};
        final byte[] b = new byte[]{'a', 'a', 'a'};
        checkEquals(a, b, "Expected array to be equal.");
    }

    @Test(expected = OtrCryptoException.class)
    public void testCheckEqualsArrayContentDiff() throws OtrCryptoException {
        final byte[] a = new byte[]{'a', 'b', 'c', 'd'};
        final byte[] b = new byte[]{'a', 'b', 'c', 'e'};
        checkEquals(a, b, "Expected array to be equal.");
    }

    @Test(expected = NullPointerException.class)
    public void testCheckEqualsNullArraysEqual() throws OtrCryptoException {
        checkEquals(null, null, "Expected array to be equal.");
    }

    @Test(expected = NullPointerException.class)
    public void testCheckEqualsOneNull1() throws OtrCryptoException {
        final byte[] a = new byte[]{'a', 'a', 'a', 'a'};
        checkEquals(a, null, "Expected array to be equal.");
    }

    @Test(expected = NullPointerException.class)
    public void testCheckEqualsOneNull2() throws OtrCryptoException {
        final byte[] b = new byte[]{'a', 'a', 'a', 'a'};
        checkEquals(null, b, "Expected array to be equal.");
    }
}
