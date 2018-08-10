package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

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

    @Test
    public void testConstructionNullDHKeyPair() {
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, null, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test
    public void testConstructionNullECDHKeyPair() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test
    public void testConstructionNullECDHandDHKeyPair() {
        new SharedSecret4(RANDOM, null, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test
    public void testConstructionNullTheirDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, null, theirECDHPublicKey);
    }

    @Test
    public void testConstructionNullTheirECDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, null);
    }

    @Test
    public void testConstructionNullTheirECDHandDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNullTooManyKeys1() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, ourDHKeyPair, null, null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNullTooManyKeys2() {
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new SharedSecret4(RANDOM, null, ourECDHKeyPair, null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNullTooManyKeys3() {
        new SharedSecret4(RANDOM, null, null, theirDHPublicKey, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNullTooManyKeys4() {
        new SharedSecret4(RANDOM, null, null, null, theirECDHPublicKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNullAllKeys() {
        new SharedSecret4(RANDOM, null, null, null, null);
    }

    @Test
    public void testConstruction() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        assertNotNull(ss.getECDHPublicKey());
        assertNotNull(ss.getDHPublicKey());
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
    public void testRotateTheirKeys() {
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
    public void testRotateTheirKeysNullECDH() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(true, null, theirNextDHPublicKey);
    }

    @Test
    public void testRotateTheirKeysNullDHNonThirdIteration() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate their public keys.
        ss.rotateTheirKeys(false, theirNextECDHPublicKey, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullDHThirdIteration() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(true, theirNextECDHPublicKey, null);
    }

    @Test
    public void testGetKNotModifiable() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(true, theirNextECDHPublicKey, theirNextDHPublicKey);
        final byte[] firstK = ss.getK();
        fill(firstK, (byte) 0xff);
        final byte[] secondK = ss.getK();
        assertFalse(Arrays.equals(firstK, secondK));
    }

    // FIXME This notes that it is possible to go back to an earlier ratchet state by providing the same public keys again, ... within reason for a short while. Is this by design?
    @Test
    public void testRotateSamePublicKeysEveryThirdIteration() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(true);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(true, theirECDHPublicKey, theirDHPublicKey);
        assertArrayEquals(firstK, ss.getK());
    }

    @Test
    public void testRotateDifferentPublicKeysEveryThirdIteration() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(true);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(true, theirNextECDHPublicKey, theirNextDHPublicKey);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateSamePublicKeysEveryNonThirdIteration() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final SharedSecret4 ss = new SharedSecret4(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(false, theirECDHPublicKey, null);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }
}
