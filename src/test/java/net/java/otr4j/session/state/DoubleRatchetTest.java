package net.java.otr4j.session.state;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.SharedSecret4TestUtils;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;

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
    public void testGenerateRotateBeforeReception() {
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, generateSharedSecret(), INITIAL_K);
        ratchet.rotateSenderKeys();
        ratchet.rotateSenderKeys();
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
    public void testMessageKeysClosedFailsVerify() throws DoubleRatchet.KeyRotationLimitationException {
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
        return SharedSecret4TestUtils.create(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
