package net.java.otr4j.session.state;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.session.state.DoubleRatchet.EncryptionResult;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.session.state.DoubleRatchet.RotationResult;
import net.java.otr4j.session.state.DoubleRatchet.VerificationException;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.SharedSecret4TestUtils.createSharedSecret4;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.random;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

// FIXME add unit tests to verify correct clearing of fields
@SuppressWarnings("ConstantConditions")
public class DoubleRatchetTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] INITIAL_K = new byte[64];

    private static final byte[] MESSAGE = "Hello world".getBytes(UTF_8);

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
    public void testEncryptionBeforeRotation() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.encrypt(MESSAGE);
    }

    @Test(expected = IllegalStateException.class)
    public void testAuthenticationBeforeRotation() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.authenticate(MESSAGE);
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateBeforeReceptionNotPermitted() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testEncryptionAfterRotation() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        final EncryptionResult result = ratchet.encrypt(MESSAGE);
        assertNotNull(result);
        assertFalse(allZeroBytes(result.nonce));
        assertFalse(allZeroBytes(result.ciphertext));
        assertFalse(Arrays.equals(MESSAGE, result.ciphertext));
    }

    @Test
    public void testAuthenticationAfterRotation() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertArrayEquals(auth1, auth2);
    }

    @Test
    public void testAuthenticatorsDifferentAfterRotation() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        final int firstMessageId = ratchet.getJ();
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        ratchet.rotateSendingChainKey();
        assertNotEquals(firstMessageId, ratchet.getJ());
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertFalse(Arrays.equals(auth1, auth2));
    }

    @Test
    public void testTwoEncryptionsDontUseSameNonce() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        // Note that encrypting twice without rotation chain key is not intended use. The only reason to support this is
        // if the message never got sent.
        final int ratchetId = ratchet.getI();
        final int messageId = ratchet.getJ();
        final EncryptionResult result = ratchet.encrypt(MESSAGE);
        final EncryptionResult result2 = ratchet.encrypt(MESSAGE);
        assertEquals(ratchetId, ratchet.getI());
        assertEquals(messageId, ratchet.getJ());
        assertFalse(allZeroBytes(result.nonce));
        assertFalse(allZeroBytes(result.ciphertext));
        assertFalse(allZeroBytes(result2.nonce));
        assertFalse(allZeroBytes(result2.ciphertext));
        assertFalse(Arrays.equals(MESSAGE, result.ciphertext));
        assertFalse(Arrays.equals(MESSAGE, result2.ciphertext));
        assertFalse(Arrays.equals(result.nonce, result2.nonce));
        assertFalse(Arrays.equals(result.ciphertext, result2.ciphertext));
    }

    @Test
    public void testRepeatedCloseIsAllowed() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.close();
        ratchet.close();
        ratchet.close();
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsEncryption() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.close();
        ratchet.encrypt(message);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsVerify() throws RotationLimitationException {
        final byte[] message = kdf1(DATA_MESSAGE_SECTIONS, "Hello World!".getBytes(UTF_8), 64);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        final byte[] authenticator = ratchet.authenticate(message);
        ratchet.close();
        ratchet.decrypt(ratchet.getI(), ratchet.getJ(), message, authenticator);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsGetExtraSymmetricKey() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.close();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testDoubleRatchetWorksSymmetrically() throws VerificationException, RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        assertNotNull(rotation.dhPublicKey);
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.verify(0, 0, message, authenticator);
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, encrypted.ciphertext, encrypted.nonce));
    }

    @Test(expected = VerificationException.class)
    public void testDoubleRatchetWorksBadAuthenticator() throws VerificationException, RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.verify(0, 0, message, random(RANDOM, new byte[64]));
    }

    @Test(expected = IllegalStateException.class)
    public void testDoubleRatchetCannotRotateSenderKeysWithoutPublicKeys() {
        // Prepare ratchets for Alice and Bob
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), random(RANDOM, new byte[64]));
        bobRatchet.rotateSenderKeys();
    }

    @Test(expected = IllegalStateException.class)
    public void testDoubleRatchetPrematureClosing() throws VerificationException, RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        final byte[] authenticator = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.verify(0, 0, message, authenticator);
        bobRatchet.close();
    }

    @Test
    public void testDoubleRatchetSkipMessagesLostMessageKeys() throws VerificationException, RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        final EncryptionResult encrypted2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.verify(0, 2, message, authenticator2);
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, encrypted2.ciphertext, encrypted2.nonce));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testDoubleRatchetRetrievePreviousMessageKeys() throws RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.rotateReceivingChainKey();
        bobRatchet.rotateReceivingChainKey();
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, encrypted.ciphertext, encrypted.nonce));
    }

    @Test(expected = RotationLimitationException.class)
    public void testDoubleRatchetSkipMessageKeysPastRatchet() throws RotationLimitationException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet.rotateSenderKeys();
        // ... in the mean time Bob rotates, encrypts messages and sends them to Alice.
        // ... Alice, however, does not receive all of them. Until, receiving message 2, 1, for which receiver keys
        // rotation is needed.
        aliceRatchet.decrypt(2, 1, random(RANDOM, new byte[0]), random(RANDOM, new byte[0]));
    }

    @Test
    public void testDoubleRatchetWorksSymmetricallyWithRotations() throws VerificationException, RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = random(RANDOM, new byte[64]);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, bobDH, bobECDH, null, null), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                createSharedSecret4(RANDOM, null, null, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        assertTrue(aliceRatchet.isNeedSenderKeyRotation());
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        assertFalse(aliceRatchet.isNeedSenderKeyRotation());
        assertArrayEquals(new byte[0], rotation.revealedMacs);
        assertNotNull(rotation.dhPublicKey);
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        aliceRatchet.rotateSendingChainKey();
        final EncryptionResult encrypted2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        aliceRatchet.rotateSendingChainKey();
        final EncryptionResult encrypted3 = aliceRatchet.encrypt(message);
        final byte[] authenticator3 = aliceRatchet.authenticate(message);
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        assertTrue(bobRatchet.isNeedSenderKeyRotation());
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        assertEquals(0, bobRatchet.getPn());
        bobRatchet.verify(0, 0, message, authenticator);
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, encrypted.ciphertext, encrypted.nonce));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(1, bobRatchet.getK());
        bobRatchet.verify(0, 1, message, authenticator2);
        assertArrayEquals(message, bobRatchet.decrypt(0, 1, encrypted2.ciphertext, encrypted2.nonce));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(2, bobRatchet.getK());
        bobRatchet.verify(0, 2, message, authenticator3);
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, encrypted3.ciphertext, encrypted3.nonce));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        // Bob starts sending response messages.
        final RotationResult rotation2 = bobRatchet.rotateSenderKeys();
        assertFalse(bobRatchet.isNeedSenderKeyRotation());
        assertArrayEquals(concatenate(authenticator, authenticator2, authenticator3), rotation2.revealedMacs);
        assertNull(rotation2.dhPublicKey);
        assertEquals(1, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final EncryptionResult encrypted4 = bobRatchet.encrypt(message);
        final byte[] authenticator4 = bobRatchet.authenticate(message);
        bobRatchet.rotateSendingChainKey();
        assertEquals(1, bobRatchet.getI());
        assertEquals(1, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final EncryptionResult encrypted5 = bobRatchet.encrypt(message);
        final byte[] authenticator5 = bobRatchet.authenticate(message);
        bobRatchet.rotateSendingChainKey();
        assertEquals(1, bobRatchet.getI());
        assertEquals(2, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final EncryptionResult encrypted6 = bobRatchet.encrypt(message);
        final byte[] authenticator6 = bobRatchet.authenticate(message);
        bobRatchet.rotateSendingChainKey();
        assertEquals(1, bobRatchet.getI());
        assertEquals(3, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        // Alice starts decrypting and verifying the responses.
        assertFalse(aliceRatchet.isNeedSenderKeyRotation());
        aliceRatchet.rotateReceiverKeys(bobRatchet.getECDHPublicKey(), rotation2.dhPublicKey);
        assertTrue(aliceRatchet.isNeedSenderKeyRotation());
        assertEquals(3, aliceRatchet.getPn());
        assertEquals(1, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(0, aliceRatchet.getK());
        aliceRatchet.verify(1, 0, message, authenticator4);
        assertArrayEquals(message, aliceRatchet.decrypt(1, 0, encrypted4.ciphertext, encrypted4.nonce));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(1, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(1, aliceRatchet.getK());
        aliceRatchet.verify(1, 1, message, authenticator5);
        assertArrayEquals(message, aliceRatchet.decrypt(1, 1, encrypted5.ciphertext, encrypted5.nonce));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(1, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(2, aliceRatchet.getK());
        aliceRatchet.verify(1, 2, message, authenticator6);
        assertArrayEquals(message, aliceRatchet.decrypt(1, 2, encrypted6.ciphertext, encrypted6.nonce));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(1, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        // Verify that Alice reveals the expected authenticators.
        final RotationResult rotation3 = aliceRatchet.rotateSenderKeys();
        assertFalse(aliceRatchet.isNeedSenderKeyRotation());
        assertArrayEquals(concatenate(authenticator4, authenticator5, authenticator6), rotation3.revealedMacs);
        assertEquals(2, aliceRatchet.getI());
        assertEquals(0, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        final EncryptionResult encrypted7 = aliceRatchet.encrypt(message);
        final byte[] authenticator7 = aliceRatchet.authenticate(message);
        aliceRatchet.rotateSendingChainKey();
        assertEquals(2, aliceRatchet.getI());
        assertEquals(1, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        assertArrayEquals(new byte[0], aliceRatchet.collectRemainingMACsToReveal());
        aliceRatchet.close();
        assertFalse(bobRatchet.isNeedSenderKeyRotation());
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation3.dhPublicKey);
        assertTrue(bobRatchet.isNeedSenderKeyRotation());
        assertEquals(3, bobRatchet.getPn());
        assertEquals(2, bobRatchet.getI());
        assertEquals(3, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        bobRatchet.verify(2, 0, message, authenticator7);
        assertArrayEquals(message, bobRatchet.decrypt(2, 0, encrypted7.ciphertext, encrypted7.nonce));
        assertArrayEquals(authenticator7, bobRatchet.collectRemainingMACsToReveal());
        bobRatchet.close();
    }

    private SharedSecret4 generateSharedSecret() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        return createSharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
