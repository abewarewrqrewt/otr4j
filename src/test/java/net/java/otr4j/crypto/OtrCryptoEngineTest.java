/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.OtrCryptoEngine.DSASignature;
import org.junit.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine.checkEquals;
import static net.java.otr4j.crypto.OtrCryptoEngine.generateDSAKeyPair;
import static net.java.otr4j.crypto.OtrCryptoEngine.signRS;
import static net.java.otr4j.crypto.OtrCryptoEngine.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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

    private static final KeyPair DSA_KEYPAIR = OtrCryptoEngine.generateDSAKeyPair();

    @Test
    public void testGeneratedSharedSecretEqual() throws OtrCryptoException {
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RAND);
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RAND);

        assertEquals(OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic()),
                OtrCryptoEngine.generateSecret(bobDHKeyPair.getPrivate(), aliceDHKeyPair.getPublic()));
    }

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

    @Test
    public void testCreateSHA256MessageDigest() {
        assertNotNull(OtrCryptoEngine.createSHA256MessageDigest());
    }

    @Test(expected = NullPointerException.class)
    public void testSignRSNullMessage() {
        signRS(null, (DSAPrivateKey) DSA_KEYPAIR.getPrivate());
    }

    @Test(expected = NullPointerException.class)
    public void testSignRSNullPrivateKey() {
        signRS(new byte[]{'m'}, null);
    }

    @Test
    public void testSignRS() throws OtrCryptoException {
        final byte[] m = "hello".getBytes(UTF_8);
        final DSASignature sig = signRS(m, (DSAPrivateKey) DSA_KEYPAIR.getPrivate());
        verify(m, (DSAPublicKey) DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test
    public void testSignRSEmptyMessage() throws OtrCryptoException {
        assumeTrue("This test can only be successful without assertions, due to safety checks.",
            !OtrCryptoEngine.class.desiredAssertionStatus());
        final byte[] m = new byte[0];
        final DSASignature sig = signRS(m, (DSAPrivateKey) DSA_KEYPAIR.getPrivate());
        verify(m, (DSAPublicKey) DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test
    public void testGenerateDSAKeyPair() {
        final KeyPair keypair = generateDSAKeyPair();
        assertNotNull(keypair);
        assertTrue(keypair.getPublic() instanceof DSAPublicKey);
        assertTrue(keypair.getPrivate() instanceof DSAPrivateKey);
    }

    @Test
    public void testGenerateDSAKeyPairDifferentKeyPairs() {
        final KeyPair keypair1 = generateDSAKeyPair();
        final KeyPair keypair2 = generateDSAKeyPair();
        final KeyPair keypair3 = generateDSAKeyPair();
        assertNotEquals(((DSAPublicKey)keypair1.getPublic()).getY(), ((DSAPublicKey)keypair2.getPublic()).getY());
        assertNotEquals(((DSAPublicKey)keypair1.getPublic()).getY(), ((DSAPublicKey)keypair3.getPublic()).getY());
        assertNotEquals(((DSAPublicKey)keypair2.getPublic()).getY(), ((DSAPublicKey)keypair3.getPublic()).getY());
        assertNotEquals(((DSAPrivateKey)keypair1.getPrivate()).getX(), ((DSAPrivateKey)keypair2.getPrivate()).getX());
        assertNotEquals(((DSAPrivateKey)keypair1.getPrivate()).getX(), ((DSAPrivateKey)keypair3.getPrivate()).getX());
        assertNotEquals(((DSAPrivateKey)keypair2.getPrivate()).getX(), ((DSAPrivateKey)keypair3.getPrivate()).getX());
    }
}
