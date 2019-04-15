/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.session.state.DoubleRatchet.RotationResult;
import net.java.otr4j.session.state.DoubleRatchet.VerificationException;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.session.state.DoubleRatchet.Role.ALICE;
import static net.java.otr4j.session.state.DoubleRatchet.Role.BOB;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

// TODO add unit tests to verify correct clearing of fields
// FIXME fix names aliceRatchet, bobRatchet when roles are inconsistent with variable names.
@SuppressWarnings("ConstantConditions")
public class DoubleRatchetTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] MESSAGE = "Hello world".getBytes(UTF_8);

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSharedSecret() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(ALICE, null, initialK);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullInitialRootKey() {
        new DoubleRatchet(ALICE, generateSharedSecret(), null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullPurpose() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(null, generateSharedSecret(), initialK);
    }

    @Test
    public void testConstructDoubleRatchet() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        new DoubleRatchet(ALICE, generateSharedSecret(), initialK);
        new DoubleRatchet(BOB, generateSharedSecret(), initialK);
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateBeforeReceptionNotPermitted() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, generateSharedSecret(), initialK);
        ratchet.rotateSenderKeys();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testEncryptionAfterRotation() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(BOB, generateSharedSecret(), initialK);
        assertTrue(ratchet.isDhRatchet());
        final byte[] ciphertext = ratchet.encrypt(MESSAGE);
        assertFalse(allZeroBytes(ciphertext));
        assertFalse(Arrays.equals(MESSAGE, ciphertext));
    }

    @Test
    public void testAuthenticationAfterRotation() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(BOB, generateSharedSecret(), initialK);
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertArrayEquals(auth1, auth2);
    }

    @Test
    public void testAuthenticatorsDifferentAfterRotation() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(BOB, generateSharedSecret(), initialK);
        assertTrue(ratchet.isDhRatchet());
        final int firstMessageId = ratchet.getJ();
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        ratchet.rotateSendingChainKey();
        assertNotEquals(firstMessageId, ratchet.getJ());
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertFalse(Arrays.equals(auth1, auth2));
    }

    @Test
    public void testRepeatedCloseIsAllowed() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, generateSharedSecret(), initialK);
        ratchet.close();
        ratchet.close();
        ratchet.close();
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsEncryption() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, generateSharedSecret(), initialK);
        ratchet.close();
        ratchet.encrypt(message);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsVerify() throws RotationLimitationException, VerificationException {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, generateSharedSecret(), initialK);
        ratchet.rotateSenderKeys();
        final byte[] authenticator = ratchet.authenticate(message);
        ratchet.close();
        ratchet.decrypt(ratchet.getI(), ratchet.getJ(), message, authenticator, new byte[0]);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsGetExtraSymmetricKey() {
        final byte[] initialK = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, generateSharedSecret(), initialK);
        ratchet.close();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testDoubleRatchetWorksSymmetricallyAliceSending() throws VerificationException, RotationLimitationException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator, ciphertext));
    }

    @Test
    public void testDoubleRatchetWorksSymmetricallyBobSending() throws VerificationException, RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        assertTrue(bobRatchet.isDhRatchet());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());
        assertFalse(aliceRatchet.isDhRatchet());

        // Start encrypting and authenticating using Bob's double ratchet.
        final byte[] ciphertext = bobRatchet.encrypt(message);
        final byte[] authenticator = bobRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        aliceRatchet.rotateReceiverKeys(1, bobRatchet.getECDHPublicKey(), bobRatchet.getDHPublicKey());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 0, message, authenticator, ciphertext));
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
        final DoubleRatchet bobRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());
        bobRatchet.rotateReceiverKeys(1, aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey());
        bobRatchet.decrypt(1, 0, message, randomBytes(RANDOM, new byte[64]), randomBytes(RANDOM, new byte[100]));
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
        final DoubleRatchet bobRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final RotationResult rotation = aliceRatchet.rotateSenderKeys();
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(1, aliceRatchet.getECDHPublicKey(), rotation.dhRatchet ? aliceRatchet.getDHPublicKey() : null);
        bobRatchet.decrypt(1, 0, message, authenticator, ciphertext);
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
        final DoubleRatchet bobRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        final byte[] ciphertext2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(1, aliceRatchet.getECDHPublicKey(), aliceRatchet.isDhRatchet() ? aliceRatchet.getDHPublicKey() : null);
        assertArrayEquals(message, bobRatchet.decrypt(1, 2, message, authenticator2, ciphertext2));
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
        final DoubleRatchet bobRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(1, aliceRatchet.getECDHPublicKey(), aliceRatchet.isDhRatchet() ? aliceRatchet.getDHPublicKey() : null);
        bobRatchet.rotateReceivingChainKey();
        bobRatchet.rotateReceivingChainKey();
        assertArrayEquals(message, bobRatchet.decrypt(1, 0, message, authenticator, ciphertext));
    }

    @Ignore("Currently, there is no RotationLimitException being thrown due to Double Ratchet redesign")
    @Test(expected = RotationLimitationException.class)
    public void testDoubleRatchetSkipMessageKeysPastRatchet() throws RotationLimitationException, VerificationException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, aliceDH, aliceECDH, bobDH.getPublicKey(), bobECDH.getPublicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        // ... in the mean time Bob rotates, encrypts messages and sends them to Alice.
        // ... Alice, however, does not receive all of them. Until, receiving message 2, 1, for which receiver keys
        // rotation is needed.
        bobRatchet.decrypt(2, 1, new byte[0], new byte[0], new byte[0]);
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
        final DoubleRatchet bobRatchet = new DoubleRatchet(BOB,
                new MixedSharedSecret(RANDOM, bobFirstDH, bobFirstECDH, aliceFirstDH.getPublicKey(),
                        aliceFirstECDH.getPublicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = new DoubleRatchet(ALICE,
                new MixedSharedSecret(RANDOM, aliceFirstDH, aliceFirstECDH, bobFirstDH.getPublicKey(),
                        bobFirstECDH.getPublicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        assertFalse(aliceRatchet.isNeedSenderKeyRotation());
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey1 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        final byte[] ciphertext2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey2 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        final byte[] ciphertext3 = aliceRatchet.encrypt(message);
        final byte[] authenticator3 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey3 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        assertFalse(bobRatchet.isNeedSenderKeyRotation());
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        assertEquals(0, bobRatchet.getPn());
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator, ciphertext));
        assertArrayEquals(extraSymmKey1, bobRatchet.extraSymmetricReceivingKey(0, 0));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(1, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(0, 1, message, authenticator2, ciphertext2));
        assertArrayEquals(extraSymmKey2, bobRatchet.extraSymmetricReceivingKey(0, 1));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(2, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, message, authenticator3, ciphertext3));
        assertArrayEquals(extraSymmKey3, bobRatchet.extraSymmetricReceivingKey(0, 2));
        bobRatchet.rotateReceivingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        // Bob starts sending response messages.
        assertFalse(bobRatchet.isNeedSenderKeyRotation());
        assertEquals(0, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final byte[] ciphertext4 = bobRatchet.encrypt(message);
        final byte[] authenticator4 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey4 = bobRatchet.extraSymmetricSendingKey();
        bobRatchet.rotateSendingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(1, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final byte[] ciphertext5 = bobRatchet.encrypt(message);
        final byte[] authenticator5 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey5 = bobRatchet.extraSymmetricSendingKey();
        bobRatchet.rotateSendingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(2, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final byte[] ciphertext6 = bobRatchet.encrypt(message);
        final byte[] authenticator6 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey6 = bobRatchet.extraSymmetricSendingKey();
        bobRatchet.rotateSendingChainKey();
        assertEquals(0, bobRatchet.getI());
        assertEquals(3, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        // Alice starts decrypting and verifying the responses.
        assertEquals(0, aliceRatchet.getPn());
        assertEquals(0, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(0, aliceRatchet.getK());
        assertTrue(bobRatchet.isDhRatchet());
        aliceRatchet.rotateReceiverKeys(1, bobRatchet.getECDHPublicKey(), bobRatchet.getDHPublicKey());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 0, message, authenticator4, ciphertext4));
        assertArrayEquals(extraSymmKey4, aliceRatchet.extraSymmetricReceivingKey(1, 0));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(0, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(1, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 1, message, authenticator5, ciphertext5));
        assertArrayEquals(extraSymmKey5, aliceRatchet.extraSymmetricReceivingKey(1, 1));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(0, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(2, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 2, message, authenticator6, ciphertext6));
        assertArrayEquals(extraSymmKey6, aliceRatchet.extraSymmetricReceivingKey(1, 2));
        aliceRatchet.rotateReceivingChainKey();
        assertEquals(0, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        // Verify that Alice reveals the expected authenticators.
        final RotationResult rotation3 = aliceRatchet.rotateSenderKeys();
        assertFalse(aliceRatchet.isNeedSenderKeyRotation());
        assertArrayEquals(concatenate(authenticator4, authenticator5, authenticator6), rotation3.revealedMacs);
        assertEquals(1, aliceRatchet.getI());
        assertEquals(0, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        final byte[] ciphertext7 = aliceRatchet.encrypt(message);
        final byte[] authenticator7 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey7 = aliceRatchet.extraSymmetricSendingKey();
        aliceRatchet.rotateSendingChainKey();
        assertEquals(1, aliceRatchet.getI());
        assertEquals(1, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        assertArrayEquals(new byte[0], aliceRatchet.collectRemainingMACsToReveal());
        aliceRatchet.close();
        assertFalse(bobRatchet.isNeedSenderKeyRotation());
        bobRatchet.rotateReceiverKeys(1, aliceRatchet.getECDHPublicKey(), rotation3.dhRatchet ? aliceRatchet.getDHPublicKey() : null);
        assertTrue(bobRatchet.isNeedSenderKeyRotation());
        assertEquals(3, bobRatchet.getPn());
        assertEquals(0, bobRatchet.getI());
        assertEquals(3, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(1, 0, message, authenticator7, ciphertext7));
        assertArrayEquals(concatenate(authenticator, authenticator2, authenticator3, authenticator7),
                bobRatchet.collectRemainingMACsToReveal());
        assertArrayEquals(extraSymmKey7, bobRatchet.extraSymmetricReceivingKey(1, 0));
        bobRatchet.close();
    }

    @Test
    public void testGenerateExtraSymmetricKeys() throws RotationLimitationException, OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, generateSharedSecret(), initialRootKey.clone());
        // Rotate sender keys and generate sender extra symmetric key
        final byte[] extraSymmSendingKey = ratchet.extraSymmetricSendingKey();
        assertNotNull(extraSymmSendingKey);
        assertFalse(allZeroBytes(extraSymmSendingKey));
        // Rotate receiver keys and generate receiver extra symmetric key
        ratchet.rotateReceiverKeys(1, ECDHKeyPair.generate(RANDOM).getPublicKey(), DHKeyPair.generate(RANDOM).getPublicKey());
        final byte[] extraSymmReceivingKey = ratchet.extraSymmetricReceivingKey(1, 0);
        assertNotNull(extraSymmReceivingKey);
        assertFalse(allZeroBytes(extraSymmReceivingKey));
    }

    private MixedSharedSecret generateSharedSecret() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        return new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
