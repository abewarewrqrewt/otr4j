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
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.SharedSecret4TestUtils.createSharedSecret4;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.random;
import static org.junit.Assert.*;

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

    private SharedSecret4 generateSharedSecret() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        return createSharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
