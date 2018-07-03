package net.java.otr4j.crypto;

import net.java.otr4j.crypto.DoubleRatchet.MessageKeys;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
    public void testGenerateReceivingMessageKeys() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final MessageKeys keys = ratchet.generateReceivingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysDoesNotProduceNullReceiverKeys() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        ratchet.rotateSenderKeys();
        final MessageKeys keys = ratchet.generateReceivingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testGenerateSendingMessageKeys() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final MessageKeys keys = ratchet.generateSendingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysDoesNotProduceNullSenderKeys() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        ratchet.rotateSenderKeys();
        final MessageKeys keys = ratchet.generateSendingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getEncrypt());
        assertNotNull(keys.getMac());
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysConfirmReceiverKeysPreserved() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final MessageKeys initialSendingKeys = ratchet.generateSendingKeys();
        final MessageKeys initialReceivingKeys = ratchet.generateReceivingKeys();
        ratchet.rotateSenderKeys();
        final MessageKeys nextSendingKeys = ratchet.generateSendingKeys();
        assertFalse(Arrays.equals(initialSendingKeys.getEncrypt(), nextSendingKeys.getEncrypt()));
        assertFalse(Arrays.equals(initialSendingKeys.getMac(), nextSendingKeys.getMac()));
        assertFalse(Arrays.equals(initialSendingKeys.getExtraSymmetricKey(), nextSendingKeys.getExtraSymmetricKey()));
        final MessageKeys nextReceivingKeys = ratchet.generateReceivingKeys();
        assertArrayEquals(initialReceivingKeys.getEncrypt(), nextReceivingKeys.getEncrypt());
        assertArrayEquals(initialReceivingKeys.getMac(), nextReceivingKeys.getMac());
        assertArrayEquals(initialReceivingKeys.getExtraSymmetricKey(), nextReceivingKeys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateReceiverKeysConfirmSenderKeysPreserved() throws OtrCryptoException {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET);
        final MessageKeys initialSendingKeys = ratchet.generateSendingKeys();
        final MessageKeys initialReceivingKeys = ratchet.generateReceivingKeys();
        ratchet.rotateReceiverKeys(THEIR_NEXT_DH_PUBLIC_KEY, THEIR_NEXT_ECDH_PUBLIC_KEY);
        final MessageKeys nextSendingKeys = ratchet.generateSendingKeys();
        assertArrayEquals(initialSendingKeys.getEncrypt(), nextSendingKeys.getEncrypt());
        assertArrayEquals(initialSendingKeys.getMac(), nextSendingKeys.getMac());
        assertArrayEquals(initialSendingKeys.getExtraSymmetricKey(), nextSendingKeys.getExtraSymmetricKey());
        final MessageKeys nextReceivingKeys = ratchet.generateReceivingKeys();
        assertFalse(Arrays.equals(initialReceivingKeys.getEncrypt(), nextReceivingKeys.getEncrypt()));
        assertFalse(Arrays.equals(initialReceivingKeys.getMac(), nextReceivingKeys.getMac()));
        assertFalse(Arrays.equals(initialReceivingKeys.getExtraSymmetricKey(), nextReceivingKeys.getExtraSymmetricKey()));
    }

    @Test
    public void testMessageKeysCloseZeroesData() {
        final MessageKeys keys;
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET)) {
            keys = ratchet.generateSendingKeys();
        }
        assertFalse(allZeroBytes(keys.getEncrypt()));
        assertFalse(allZeroBytes(keys.getMac()));
        assertFalse(allZeroBytes(keys.getExtraSymmetricKey()));
        keys.close();
        assertTrue(allZeroBytes(keys.getEncrypt()));
        assertTrue(allZeroBytes(keys.getMac()));
        assertTrue(allZeroBytes(keys.getExtraSymmetricKey()));
    }

    @Test
    public void testMessageKeysCloseDoesNotZeroReturnedKeys() {
        final MessageKeys keys;
        final byte[] encrypt;
        final byte[] mac;
        final byte[] extraKey;
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, SHARED_SECRET)) {
            keys = ratchet.generateSendingKeys();
            encrypt = keys.getEncrypt();
            mac = keys.getMac();
            extraKey = keys.getExtraSymmetricKey();
            assertFalse(allZeroBytes(encrypt));
            assertFalse(allZeroBytes(mac));
            assertFalse(allZeroBytes(extraKey));
            keys.close();
        }
        assertTrue(allZeroBytes(keys.getEncrypt()));
        assertTrue(allZeroBytes(keys.getMac()));
        assertTrue(allZeroBytes(keys.getExtraSymmetricKey()));
        assertFalse(allZeroBytes(encrypt));
        assertFalse(allZeroBytes(mac));
        assertFalse(allZeroBytes(extraKey));
    }
}
