package net.java.otr4j.session.state;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.SharedSecret4TestUtils;
import net.java.otr4j.session.state.DoubleRatchet.MessageKeys;
import net.java.otr4j.session.state.DoubleRatchet.Result;
import net.java.otr4j.session.state.DoubleRatchet.VerificationException;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

@SuppressWarnings("ConstantConditions")
// FIXME add unit tests to verify correct clearing of fields
public class DoubleRatchetTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] INITIAL_K = new byte[64];

    static {
        RANDOM.nextBytes(INITIAL_K);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSecureRandom() {
        new DoubleRatchet(null, generateSharedSecret(), INITIAL_K);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSharedSecret() {
        new DoubleRatchet(RANDOM, null, INITIAL_K);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullInitialRootKey() {
        new DoubleRatchet(RANDOM, generateSharedSecret(), null);
    }

    @Test
    public void testConstructDoubleRatchet() {
        new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateBeforeRotationFails() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.generateSendingKeys();
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateRotateBeforeReception() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testGenerateReceivingMessageKeys() throws DoubleRatchet.KeyRotationLimitation {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        final ECDHKeyPair nextECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair nextDH = DHKeyPair.generate(RANDOM);
        ratchet.rotateReceiverKeys(nextECDH.getPublicKey(), nextDH.getPublicKey());
        final MessageKeys keys = ratchet.generateReceivingKeys(ratchet.getI()-1, ratchet.getK());
        assertNotNull(keys);
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testRotateSenderKeysDoesNotProduceNullReceiverKeys() throws DoubleRatchet.KeyRotationLimitation {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        final ECDHKeyPair nextECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair nextDH = DHKeyPair.generate(RANDOM);
        ratchet.rotateReceiverKeys(nextECDH.getPublicKey(), nextDH.getPublicKey());
        final MessageKeys keys = ratchet.generateReceivingKeys(ratchet.getI()-1, ratchet.getK());
        assertNotNull(keys);
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testGenerateSendingMessageKeys() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        final MessageKeys keys = ratchet.generateSendingKeys();
        assertNotNull(keys);
        assertNotNull(keys.getExtraSymmetricKey());
    }

    @Test
    public void testMessageKeysCloseDoesNotZeroReturnedKeys() {
        final MessageKeys keys;
        final byte[] extraKey;
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            ratchet.rotateSenderKeys();
            keys = ratchet.generateSendingKeys();
            extraKey = keys.getExtraSymmetricKey();
            assertFalse(allZeroBytes(extraKey));
            keys.close();
        }
        assertFalse(allZeroBytes(extraKey));
    }

    @Test
    public void testMessageKeysEncryptDecrypt() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            ratchet.rotateSenderKeys();
            try (final MessageKeys keys = ratchet.generateSendingKeys()) {
                final Result encrypted = keys.encrypt(message);
                assertNotNull(encrypted);
                assertNotEquals(0L, encrypted.nonce);
                assertFalse(Arrays.equals(message, encrypted.ciphertext));
                assertArrayEquals(message, keys.decrypt(encrypted.ciphertext, encrypted.nonce));
            }
        }
    }

    @Test
    public void testRepeatedCloseIsAllowed() {
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            ratchet.rotateSenderKeys();
            final MessageKeys keys = ratchet.generateSendingKeys();
            keys.close();
            keys.close();
            keys.close();
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsEncryption() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            final MessageKeys keys = ratchet.generateSendingKeys();
            keys.close();
            keys.encrypt(message);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsDecryption() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            final MessageKeys keys;
            final Result encrypted;
            try {
                ratchet.rotateSenderKeys();
                keys = ratchet.generateSendingKeys();
                encrypted = keys.encrypt(message);
                keys.close();
            } catch (final RuntimeException e) {
                fail("Expected this part of the test to succeed.");
                throw new RuntimeException("Cannot reach this.");
            }
            keys.decrypt(encrypted.ciphertext, encrypted.nonce);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsAuthenticate() {
        final byte[] message = kdf1(DATA_MESSAGE_SECTIONS, "Hello World!".getBytes(UTF_8), 64);
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            final MessageKeys keys = ratchet.generateSendingKeys();
            keys.close();
            keys.authenticate(message);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsVerify() throws VerificationException {
        final byte[] message = kdf1(DATA_MESSAGE_SECTIONS, "Hello World!".getBytes(UTF_8), 64);
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            final MessageKeys keys;
            final byte[] authenticator;
            try {
                ratchet.rotateSenderKeys();
                keys = ratchet.generateSendingKeys();
                authenticator = keys.authenticate(message);
                keys.close();
            } catch (final RuntimeException e) {
                fail("Expected this part of the test to succeed.");
                throw new RuntimeException("Cannot reach this.");
            }
            keys.verify(message, authenticator);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsGetExtraSymmetricKey() {
        try (final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K)) {
            ratchet.rotateSenderKeys();
            final MessageKeys keys = ratchet.generateSendingKeys();
            keys.close();
            keys.getExtraSymmetricKey();
        }
    }

    private SharedSecret4 generateSharedSecret() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        return SharedSecret4TestUtils.create(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
