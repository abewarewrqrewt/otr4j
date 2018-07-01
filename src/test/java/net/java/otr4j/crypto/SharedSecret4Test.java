package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

/**
 * The SharedSecret4 tests currently do not perform a test that binary-exactly verifies that the right values are
 * produced. For now we verify immutability of values and that values change after rotation.
 */
@SuppressWarnings("ConstantConditions")
// FIXME add unit tests to verify correct clearing of fields
public class SharedSecret4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);

    private static final DHKeyPair ourNextDHKeyPair = DHKeyPair.generate(RANDOM);

    private static final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);

    private static final ECDHKeyPair ourNextECDHKeyPair = ECDHKeyPair.generate(RANDOM);

    private static final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final Point theirNextECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger theirNextDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();

    @Test(expected = NullPointerException.class)
    public void testConstructionNullDHKeyPair() throws OtrCryptoException {
        new SharedSecret4(null, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHKeyPair() throws OtrCryptoException {
        new SharedSecret4(ourDHKeyPair, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirDHPublicKey() throws OtrCryptoException {
        new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, null, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHPublicKey() throws OtrCryptoException {
        new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, null);
    }

    @Test
    public void testConstruction() throws OtrCryptoException {
        new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test
    public void testRotateOurKeys() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateOurKeys(1, ourNextECDHKeyPair, ourNextDHKeyPair);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateOurKeysNullECDH() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(1, null, ourNextDHKeyPair);
    }

    @Test
    public void testRotateOurKeysNullDHOnNonThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // DH key pair is not used on any non-third iteration.
        ss.rotateOurKeys(1, ourNextECDHKeyPair, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateOurKeysNullDHOnThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(3, ourNextECDHKeyPair, null);
    }

    @Test
    public void testRotateTheirKeys() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateTheirKeys(1, theirNextECDHPublicKey, theirNextDHPublicKey);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullECDH() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(1, null, theirNextDHPublicKey);
    }

    @Test
    public void testRotateTheirKeysNullDHNonThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate their public keys.
        ss.rotateTheirKeys(1, theirNextECDHPublicKey, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullDHThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(3, theirNextECDHPublicKey, null);
    }

    @Test
    public void testGetKNotModifiable() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(0, theirNextECDHPublicKey, theirNextDHPublicKey);
        final byte[] firstK = ss.getK();
        fill(firstK, (byte) 0xff);
        final byte[] secondK = ss.getK();
        assertFalse(Arrays.equals(firstK, secondK));
    }

    // FIXME This notes that it is possible to go back to an earlier ratchet state by providing the same public keys again, ... within reason for a short while. Is this by design?
    @Test
    public void testRotateSamePublicKeysEveryThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(0, theirECDHPublicKey, theirDHPublicKey);
        assertArrayEquals(firstK, ss.getK());
    }

    @Test
    public void testRotateSamePublicKeysEveryNonThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(1, theirECDHPublicKey, null);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }
}
