package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.EdDSAKeyPair.generate;
import static net.java.otr4j.crypto.EdDSAKeyPair.verify;
import static nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings("ConstantConditions")
public final class EdDSAKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair keypair = generate(RANDOM);

    @Test(expected = NullPointerException.class)
    public void testGenerateNullRandom() {
        generate(null);
    }

    @Test
    public void testGenerateKeyPair() {
        assertNotNull(generate(RANDOM));
    }

    @Test
    public void testRegeneratePublicKey() {
        final Point expected = this.keypair.getPublicKey();
        final Point generated = multiplyByBase(this.keypair.getSecretKey());
        assertEquals(expected.x(), generated.x());
        assertEquals(expected.y(), generated.y());
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullMessage() {
        this.keypair.sign(null);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullPublicKey() throws OtrCryptoException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(null, message, sig);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullMessage() throws OtrCryptoException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(this.keypair.getPublicKey(), null, sig);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullSignature() throws OtrCryptoException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        verify(this.keypair.getPublicKey(), message, null);
    }

    @Test
    public void testSignatureIsVerifiable() throws OtrCryptoException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(this.keypair.getPublicKey(), message, sig);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyWrongPublicKey() throws OtrCryptoException {
        final EdDSAKeyPair keypair2 = EdDSAKeyPair.generate(RANDOM);
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(keypair2.getPublicKey(), message, sig);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyWrongMessage() throws OtrCryptoException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(this.keypair.getPublicKey(), "bladkfjsaf".getBytes(UTF_8), sig);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyWrongSignature() throws OtrCryptoException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        sig[0] = 0;
        verify(this.keypair.getPublicKey(), message, sig);
    }
}
