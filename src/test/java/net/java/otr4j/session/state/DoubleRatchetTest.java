/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.session.state.DoubleRatchet.EncryptionResult;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.session.state.DoubleRatchet.RotationResult;
import net.java.otr4j.session.state.DoubleRatchet.VerificationException;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.session.state.DoubleRatchet.Purpose.RECEIVER;
import static net.java.otr4j.session.state.DoubleRatchet.Purpose.SENDER;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

// TODO add unit tests to verify correct clearing of fields
@SuppressWarnings("ConstantConditions")
public class DoubleRatchetTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] MESSAGE = "Hello world".getBytes(UTF_8);

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSecureRandom() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(null, generateSharedSecret(), initialK, SENDER);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSharedSecret() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(RANDOM, null, initialK, SENDER);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullInitialRootKey() {
        new DoubleRatchet(RANDOM, generateSharedSecret(), null, SENDER);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullPurpose() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, null);
    }

    @Test
    public void testConstructDoubleRatchet() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, SENDER);
        new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, RECEIVER);
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateBeforeReceptionNotPermitted() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, SENDER);
        ratchet.rotateSenderKeys();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testEncryptionAfterRotation() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, RECEIVER);
        ratchet.rotateSenderKeys();
        final EncryptionResult result = ratchet.encrypt(MESSAGE);
        assertNotNull(result);
        assertFalse(allZeroBytes(result.nonce));
        assertFalse(allZeroBytes(result.ciphertext));
        assertFalse(Arrays.equals(MESSAGE, result.ciphertext));
    }

    @Test
    public void testAuthenticationAfterRotation() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, RECEIVER);
        ratchet.rotateSenderKeys();
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertArrayEquals(auth1, auth2);
    }

    @Test
    public void testAuthenticatorsDifferentAfterRotation() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, RECEIVER);
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
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, RECEIVER);
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
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, SENDER);
        ratchet.close();
        ratchet.close();
        ratchet.close();
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsEncryption() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, SENDER);
        ratchet.close();
        ratchet.encrypt(message);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsVerify() throws RotationLimitationException, VerificationException {
        final byte[] message = kdf1(DATA_MESSAGE_SECTIONS, "Hello World!".getBytes(UTF_8), 64);
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, SENDER);
        ratchet.rotateSenderKeys();
        final byte[] authenticator = ratchet.authenticate(message);
        ratchet.close();
        ratchet.decrypt(ratchet.getI(), ratchet.getJ(), message, authenticator, new byte[0], new byte[0]);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsGetExtraSymmetricKey() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialK, SENDER);
        ratchet.close();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testDoubleRatchetWorksSymmetrically() throws VerificationException, RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone(), SENDER);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone(), RECEIVER);

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        assertNotNull(rotation.dhPublicKey);
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator,
                encrypted.ciphertext, encrypted.nonce));
    }

    @Test(expected = VerificationException.class)
    public void testDoubleRatchetWorksBadAuthenticator() throws VerificationException, RotationLimitationException,
            OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone(), SENDER);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone(), RECEIVER);
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.decrypt(0, 0, message, randomBytes(RANDOM, new byte[64]), randomBytes(RANDOM, new byte[100]),
                new byte[24]);
    }

    @Test(expected = IllegalStateException.class)
    public void testDoubleRatchetPrematureClosing() throws VerificationException, RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone(), SENDER);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone(), RECEIVER);

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.decrypt(0, 0, message, authenticator, encrypted.ciphertext, encrypted.nonce);
        bobRatchet.close();
    }

    @Test
    public void testDoubleRatchetSkipMessagesLostMessageKeys() throws VerificationException, RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone(), SENDER);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone(), RECEIVER);

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        final EncryptionResult encrypted2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, message, authenticator2,
                encrypted2.ciphertext, encrypted2.nonce));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testDoubleRatchetRetrievePreviousMessageKeys() throws RotationLimitationException, OtrCryptoException,
            VerificationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone(), SENDER);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone(), RECEIVER);

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        bobRatchet.rotateReceivingChainKey();
        bobRatchet.rotateReceivingChainKey();
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator,
                encrypted.ciphertext, encrypted.nonce));
    }

    @Test(expected = RotationLimitationException.class)
    public void testDoubleRatchetSkipMessageKeysPastRatchet() throws RotationLimitationException, VerificationException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceDH, aliceECDH, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone(), RECEIVER);

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet.rotateSenderKeys();
        // ... in the mean time Bob rotates, encrypts messages and sends them to Alice.
        // ... Alice, however, does not receive all of them. Until, receiving message 2, 1, for which receiver keys
        // rotation is needed.
        aliceRatchet.decrypt(2, 1, new byte[0], new byte[0], new byte[0], new byte[0]);
    }

    @Test
    public void testDoubleRatchetWorksSymmetricallyWithRotations() throws VerificationException, RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone(), SENDER);
        final DoubleRatchet aliceRatchet = new DoubleRatchet(RANDOM,
                new SharedSecret4(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone(), RECEIVER);

        // Start encrypting and authenticating using Bob's double ratchet.
        assertTrue(aliceRatchet.isNeedSenderKeyRotation());
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        assertFalse(aliceRatchet.isNeedSenderKeyRotation());
        assertArrayEquals(new byte[0], rotation.revealedMacs);
        assertNotNull(rotation.dhPublicKey);
        final EncryptionResult encrypted = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey1 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        final EncryptionResult encrypted2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey2 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        final EncryptionResult encrypted3 = aliceRatchet.encrypt(message);
        final byte[] authenticator3 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey3 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), rotation.dhPublicKey);
        assertTrue(bobRatchet.isNeedSenderKeyRotation());
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        assertEquals(0, bobRatchet.getPn());
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator,
                encrypted.ciphertext, encrypted.nonce));
        assertArrayEquals(extraSymmKey1, bobRatchet.extraSymmetricReceivingKey(0, 0));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(1, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(0, 1, message, authenticator2,
                encrypted2.ciphertext, encrypted2.nonce));
        assertArrayEquals(extraSymmKey2, bobRatchet.extraSymmetricReceivingKey(0, 1));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(2, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, message, authenticator3,
                encrypted3.ciphertext, encrypted3.nonce));
        assertArrayEquals(extraSymmKey3, bobRatchet.extraSymmetricReceivingKey(0, 2));
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
        final byte[] extraSymmKey4 = bobRatchet.extraSymmetricSendingKey();
        bobRatchet.rotateSendingChainKey();
        assertEquals(1, bobRatchet.getI());
        assertEquals(1, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final EncryptionResult encrypted5 = bobRatchet.encrypt(message);
        final byte[] authenticator5 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey5 = bobRatchet.extraSymmetricSendingKey();
        bobRatchet.rotateSendingChainKey();
        assertEquals(1, bobRatchet.getI());
        assertEquals(2, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final EncryptionResult encrypted6 = bobRatchet.encrypt(message);
        final byte[] authenticator6 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey6 = bobRatchet.extraSymmetricSendingKey();
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
        assertArrayEquals(message, aliceRatchet.decrypt(1, 0, message, authenticator4,
                encrypted4.ciphertext, encrypted4.nonce));
        assertArrayEquals(extraSymmKey4, aliceRatchet.extraSymmetricReceivingKey(1, 0));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(1, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(1, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 1, message, authenticator5,
                encrypted5.ciphertext, encrypted5.nonce));
        assertArrayEquals(extraSymmKey5, aliceRatchet.extraSymmetricReceivingKey(1, 1));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(1, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(2, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 2, message, authenticator6,
                encrypted6.ciphertext, encrypted6.nonce));
        assertArrayEquals(extraSymmKey6, aliceRatchet.extraSymmetricReceivingKey(1, 2));
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
        final byte[] extraSymmKey7 = aliceRatchet.extraSymmetricSendingKey();
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
        assertArrayEquals(message, bobRatchet.decrypt(2, 0, message, authenticator7,
                encrypted7.ciphertext, encrypted7.nonce));
        assertArrayEquals(authenticator7, bobRatchet.collectRemainingMACsToReveal());
        assertArrayEquals(extraSymmKey7, bobRatchet.extraSymmetricReceivingKey(2, 0));
        bobRatchet.close();
    }

    @Test
    public void testGenerateExtraSymmetricKeys() throws RotationLimitationException, OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), initialRootKey.clone(), RECEIVER);
        // Rotate sender keys and generate sender extra symmetric key
        ratchet.rotateSenderKeys();
        final byte[] extraSymmSendingKey = ratchet.extraSymmetricSendingKey();
        assertNotNull(extraSymmSendingKey);
        assertFalse(allZeroBytes(extraSymmSendingKey));
        // Rotate receiver keys and generate receiver extra symmetric key
        ratchet.rotateReceiverKeys(ECDHKeyPair.generate(RANDOM).getPublicKey(), DHKeyPair.generate(RANDOM).getPublicKey());
        final byte[] extraSymmReceivingKey = ratchet.extraSymmetricReceivingKey(1, 0);
        assertNotNull(extraSymmReceivingKey);
        assertFalse(allZeroBytes(extraSymmReceivingKey));
    }

    private SharedSecret4 generateSharedSecret() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        return new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
