package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.*;

@SuppressWarnings("ConstantConditions")
// FIXME add unit tests to verify correct clearing of fields
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
    public void testGetSSIDNotModifiable() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final byte[] firstSSID = ratchet.generateSSID();
        fill(firstSSID, (byte) 0xff);
        final byte[] secondSSID = ratchet.generateSSID();
        assertFalse(Arrays.equals(firstSSID, secondSSID));
    }

    @Test
    public void testGenerateReceivingMessageKeys() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final DoubleRatchet.MessageKeys keys = ratchet.generateReceivingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysDoesNotProduceNullReceiverKeys() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        ratchet.rotateSenderKeys();
        final DoubleRatchet.MessageKeys keys = ratchet.generateReceivingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testGenerateSendingMessageKeys() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final DoubleRatchet.MessageKeys keys = ratchet.generateSendingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysDoesNotProduceNullSenderKeys() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        ratchet.rotateSenderKeys();
        final DoubleRatchet.MessageKeys keys = ratchet.generateSendingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysConfirmReceiverKeysPreserved() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final byte[] initialSSID = ratchet.generateSSID();
        final DoubleRatchet.MessageKeys initialSendingKeys = ratchet.generateSendingKeys();
        final DoubleRatchet.MessageKeys initialReceivingKeys = ratchet.generateReceivingKeys();
        ratchet.rotateSenderKeys();
        final byte[] nextSSID = ratchet.generateSSID();
        assertFalse(Arrays.equals(initialSSID, nextSSID));
        final DoubleRatchet.MessageKeys nextSendingKeys = ratchet.generateSendingKeys();
        assertFalse(Arrays.equals(initialSendingKeys.getEncrypt(), nextSendingKeys.getEncrypt()));
        assertFalse(Arrays.equals(initialSendingKeys.getMac(), nextSendingKeys.getMac()));
        assertFalse(Arrays.equals(initialSendingKeys.getExtraSymmetricKey(), nextSendingKeys.getExtraSymmetricKey()));
        final DoubleRatchet.MessageKeys nextReceivingKeys = ratchet.generateReceivingKeys();
        assertArrayEquals(initialReceivingKeys.getEncrypt(), nextReceivingKeys.getEncrypt());
        assertArrayEquals(initialReceivingKeys.getMac(), nextReceivingKeys.getMac());
        assertArrayEquals(initialReceivingKeys.getExtraSymmetricKey(), nextReceivingKeys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateReceiverKeysConfirmSenderKeysPreserved() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final byte[] initialSSID = ratchet.generateSSID();
        final DoubleRatchet.MessageKeys initialSendingKeys = ratchet.generateSendingKeys();
        final DoubleRatchet.MessageKeys initialReceivingKeys = ratchet.generateReceivingKeys();
        ratchet.rotateReceiverKeys(THEIR_NEXT_DH_PUBLIC_KEY, THEIR_NEXT_ECDH_PUBLIC_KEY);
        final byte[] nextSSID = ratchet.generateSSID();
        assertFalse(Arrays.equals(initialSSID, nextSSID));
        final DoubleRatchet.MessageKeys nextSendingKeys = ratchet.generateSendingKeys();
        assertArrayEquals(initialSendingKeys.getEncrypt(), nextSendingKeys.getEncrypt());
        assertArrayEquals(initialSendingKeys.getMac(), nextSendingKeys.getMac());
        assertArrayEquals(initialSendingKeys.getExtraSymmetricKey(), nextSendingKeys.getExtraSymmetricKey());
        final DoubleRatchet.MessageKeys nextReceivingKeys = ratchet.generateReceivingKeys();
        assertFalse(Arrays.equals(initialReceivingKeys.getEncrypt(), nextReceivingKeys.getEncrypt()));
        assertFalse(Arrays.equals(initialReceivingKeys.getMac(), nextReceivingKeys.getMac()));
        assertFalse(Arrays.equals(initialReceivingKeys.getExtraSymmetricKey(), nextReceivingKeys.getExtraSymmetricKey()));
    }
}
