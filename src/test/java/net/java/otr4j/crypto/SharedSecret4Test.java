package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.assertFalse;

@SuppressWarnings("ConstantConditions")
public class SharedSecret4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);

    private static final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);

    private static final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();

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
        final byte[] firstSSID = ss.getSSID();
        // Rotate our key pairs.
        final DHKeyPair nextDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair nextECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        ss.rotateOurKeys(1, nextECDHKeyPair, nextDHKeyPair);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstSSID, ss.getSSID()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateOurKeysNullECDH() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final DHKeyPair nextDHKeyPair = DHKeyPair.generate(RANDOM);
        ss.rotateOurKeys(1, null, nextDHKeyPair);
    }

    @Test
    public void testRotateOurKeysNullDHOnNonThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        final byte[] firstSSID = ss.getSSID();
        final ECDHKeyPair nextECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        // DH key pair is not used on any non-third iteration.
        ss.rotateOurKeys(1, nextECDHKeyPair, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstSSID, ss.getSSID()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateOurKeysNullDHOnThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final ECDHKeyPair nextECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        ss.rotateOurKeys(3, nextECDHKeyPair, null);
    }

    @Test
    public void testRotateTheirKeys() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        final byte[] firstSSID = ss.getSSID();
        // Rotate our key pairs.
        final BigInteger theirDHPublicKey= DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        ss.rotateTheirKeys(1, theirECDHPublicKey, theirDHPublicKey);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstSSID, ss.getSSID()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullECDH() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final BigInteger theirNextPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        ss.rotateTheirKeys(1, null, theirNextPublicKey);
    }

    @Test
    public void testRotateTheirKeysNullDHNonThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        final byte[] firstSSID = ss.getSSID();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        // Rotate their public keys.
        ss.rotateTheirKeys(1, theirECDHPublicKey, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstSSID, ss.getSSID()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullDHThirdIteration() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        ss.rotateTheirKeys(3, theirECDHPublicKey, null);
    }

    @Test
    public void testGetKNotModifiable() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        ss.rotateTheirKeys(0, theirECDHPublicKey, theirDHPublicKey);
        final byte[] firstK = ss.getK();
        fill(firstK, (byte) 0xff);
        final byte[] secondK = ss.getK();
        assertFalse(Arrays.equals(firstK, secondK));
    }

    @Test
    public void testGetSSIDNotModifiable() throws OtrCryptoException {
        final SharedSecret4 ss = new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        ss.rotateTheirKeys(0, theirECDHPublicKey, theirDHPublicKey);
        final byte[] firstSSID = ss.getSSID();
        fill(firstSSID, (byte) 0xff);
        final byte[] secondSSID = ss.getSSID();
        assertFalse(Arrays.equals(firstSSID, secondSSID));
    }
}
