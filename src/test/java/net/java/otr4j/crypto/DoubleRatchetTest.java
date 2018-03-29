package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.*;

public class DoubleRatchetTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final SharedSecret4 SHARED_SECRET;

    private static final Point THEIR_NEXT_ECDH_PUBLIC_KEY;

    private static final BigInteger THEIR_NEXT_DH_PUBLIC_KEY;

    static {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        try {
            SHARED_SECRET = new SharedSecret4(dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
            THEIR_NEXT_ECDH_PUBLIC_KEY = ECDHKeyPair.generate(RANDOM).getPublicKey();
            THEIR_NEXT_DH_PUBLIC_KEY = DHKeyPair.generate(RANDOM).getPublicKey();
        } catch (OtrCryptoException e) {
            throw new IllegalStateException("Failed to initialize tests with randomly generated key material.");
        }
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSecureRandom() {
        new DoubleRatchet(null, SHARED_SECRET);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSharedSecret() {
        new DoubleRatchet(RANDOM, null);
    }

    @Test
    public void testConstructDoubleRatchet() {
        new DoubleRatchet(RANDOM, SHARED_SECRET);
    }

    @Test
    public void testRepeatedlyCallingGenerateSSIDProducesSameResult() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        assertArrayEquals("Repeatedly generating SSIDs would expect to deliver the same result as long as ratchet has not progressed.",
            ratchet.generateSSID(), ratchet.generateSSID());
    }
    @Test
    public void testGetSSIDNotModifiable() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final byte[] firstSSID = ratchet.generateSSID();
        fill(firstSSID, (byte) 0xff);
        final byte[] secondSSID = ratchet.generateSSID();
        assertFalse(Arrays.equals(firstSSID, secondSSID));
    }

}
