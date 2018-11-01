/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.OtrCryptoEngine.DSASignature;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine.checkEquals;
import static net.java.otr4j.crypto.OtrCryptoEngine.generateDSAKeyPair;
import static net.java.otr4j.crypto.OtrCryptoEngine.signRS;
import static net.java.otr4j.crypto.OtrCryptoEngine.verify;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * Tests for OtrCryptoEngine.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class OtrCryptoEngineTest {

    private static final SecureRandom RAND = new SecureRandom();

    private static final DSAKeyPair DSA_KEYPAIR = generateDSAKeyPair();

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

    @Test(expected = NullPointerException.class)
    public void testSignRSNullMessage() {
        signRS(null, DSA_KEYPAIR.getPrivate());
    }

    @Test(expected = NullPointerException.class)
    public void testSignRSNullPrivateKey() {
        signRS(new byte[]{'m'}, null);
    }

    @Test
    public void testSignRS() throws OtrCryptoException {
        final byte[] m = "hello".getBytes(UTF_8);
        final DSASignature sig = signRS(m, DSA_KEYPAIR.getPrivate());
        verify(m, DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test
    public void testSignRSEmptyMessage() throws OtrCryptoException {
        assumeTrue("This test can only be successful without assertions, due to safety checks.",
            !OtrCryptoEngine.class.desiredAssertionStatus());
        final byte[] m = new byte[0];
        final DSASignature sig = signRS(m, DSA_KEYPAIR.getPrivate());
        verify(m, DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test
    public void testGenerateDSAKeyPair() {
        final DSAKeyPair keypair = generateDSAKeyPair();
        assertNotNull(keypair);
        assertTrue(keypair.getPublic() instanceof DSAPublicKey);
        assertTrue(keypair.getPrivate() instanceof DSAPrivateKey);
    }

    @Test
    public void testGenerateDSAKeyPairDifferentKeyPairs() {
        final DSAKeyPair keypair1 = generateDSAKeyPair();
        final DSAKeyPair keypair2 = generateDSAKeyPair();
        final DSAKeyPair keypair3 = generateDSAKeyPair();
        assertNotEquals(keypair1.getPublic().getY(), keypair2.getPublic().getY());
        assertNotEquals(keypair1.getPublic().getY(), keypair3.getPublic().getY());
        assertNotEquals(keypair2.getPublic().getY(), keypair3.getPublic().getY());
        assertNotEquals(keypair1.getPrivate().getX(), keypair2.getPrivate().getX());
        assertNotEquals(keypair1.getPrivate().getX(), keypair3.getPrivate().getX());
        assertNotEquals(keypair2.getPrivate().getX(), keypair3.getPrivate().getX());
    }
}
