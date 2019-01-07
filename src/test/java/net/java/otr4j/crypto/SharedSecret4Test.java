/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * The SharedSecret4 tests currently do not perform a test that binary-exactly verifies that the right values are
 * produced. For now we verify immutability of values and that values change after rotation.
 */
// FIXME add unit tests to verify correct clearing of fields
@SuppressWarnings("ConstantConditions")
public class SharedSecret4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final Point theirNextECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger theirNextDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSecureRandom() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(null, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullDHKeyPair() {
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, null, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHKeyPair() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHandDHKeyPair() {
        new SharedSecret4(RANDOM, null, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, null, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHandDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, null, null);
    }

    @Test
    public void testConstruction() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        assertEquals(ourECDHKeyPair.getPublicKey(), ss.getECDHPublicKey());
        assertEquals(ourDHKeyPair.getPublicKey(), ss.getDHPublicKey());
        assertEquals(theirECDHPublicKey, ss.getTheirECDHPublicKey());
        assertEquals(theirDHPublicKey, ss.getTheirDHPublicKey());
        assertNotNull(ss.getK());
    }

    @Test
    public void testRotateOurKeysNoDHRatchet() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final Point firstECDHPublicKey = ss.getECDHPublicKey();
        final BigInteger firstDHPublicKey = ss.getDHPublicKey();
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateOurKeys(false);
        // Ensure that k actually changes after rotation.
        assertNotEquals(firstECDHPublicKey, ss.getECDHPublicKey());
        assertEquals(firstDHPublicKey, ss.getDHPublicKey());
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateOurKeysDHRatchet() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final Point firstECDHPublicKey = ss.getECDHPublicKey();
        final BigInteger firstDHPublicKey = ss.getDHPublicKey();
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateOurKeys(true);
        // Ensure that k actually changes after rotation.
        assertNotEquals(firstECDHPublicKey, ss.getECDHPublicKey());
        assertNotEquals(firstDHPublicKey, ss.getDHPublicKey());
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateTheirKeys() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateTheirKeys(false, theirNextECDHPublicKey, theirNextDHPublicKey);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullECDH() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(true, null, theirNextDHPublicKey);
    }

    @Test
    public void testRotateTheirKeysNullDHNonThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        final byte[] firstSSID = ss.generateSSID();
        // Rotate their public keys.
        ss.rotateTheirKeys(false, theirNextECDHPublicKey, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstSSID, ss.generateSSID()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullDHThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(true, theirNextECDHPublicKey, null);
    }

    @Test
    public void testGetKNotModifiable() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(true, theirNextECDHPublicKey, theirNextDHPublicKey);
        final byte[] firstK = ss.getK();
        fill(firstK, (byte) 0xff);
        final byte[] secondK = ss.getK();
        assertFalse(Arrays.equals(firstK, secondK));
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateSamePublicKeysEveryThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(true);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(true, theirECDHPublicKey, theirDHPublicKey);
        assertArrayEquals(firstK, ss.getK());
    }

    @Test
    public void testRotateDifferentPublicKeysEveryThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(true);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(true, theirNextECDHPublicKey, theirNextDHPublicKey);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateSamePublicKeysEveryNonThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(false, theirECDHPublicKey, null);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateOurKeysWithoutTheirKeysNoDHKeyPairRotation() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 shared = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        shared.rotateOurKeys(false);
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysWithNullECDHPoint() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(true, null, DHKeyPair.generate(RANDOM).getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysWithIllegalECDHPoint() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(true, null, DHKeyPair.generate(RANDOM).getPublicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithOurECDHPublicKey() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 shared = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair,
                DHKeyPair.generate(RANDOM).getPublicKey(), ECDHKeyPair.generate(RANDOM).getPublicKey());
        shared.rotateTheirKeys(true, ourECDHKeyPair.getPublicKey(),
                DHKeyPair.generate(RANDOM).getPublicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithOurDHPublicKey() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 shared = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair,
                DHKeyPair.generate(RANDOM).getPublicKey(), ECDHKeyPair.generate(RANDOM).getPublicKey());
        shared.rotateTheirKeys(true, ECDHKeyPair.generate(RANDOM).getPublicKey(),
                ourDHKeyPair.getPublicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithTheirCurrentECDHPublicKey() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(true, theirECDHPublicKey, DHKeyPair.generate(RANDOM).getPublicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithTheirCurrentDHPublicKey() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(true, ECDHKeyPair.generate(RANDOM).getPublicKey(), theirDHPublicKey);
    }

    @Test
    public void testCloseSharedSecret4() {
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertTrue(allZeroBytes(shared.getK()));
    }

    @Ignore("FIXME Need to check current state to discover that SharedSecret4 is closed already.")
    @Test(expected = IllegalStateException.class)
    public void testRotateTheirKeysAfterClosing() throws OtrCryptoException {
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertTrue(allZeroBytes(shared.getK()));
        shared.rotateTheirKeys(true, ECDHKeyPair.generate(RANDOM).getPublicKey(), theirDHPublicKey);
    }

    @Ignore("FIXME Need to check current state to discover that SharedSecret4 is closed already.")
    @Test(expected = IllegalStateException.class)
    public void testRotateOurKeysAfterClosing() {
        final SharedSecret4 shared = new SharedSecret4(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertTrue(allZeroBytes(shared.getK()));
        shared.rotateOurKeys(true);
    }
}
