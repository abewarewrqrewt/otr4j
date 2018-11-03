/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.EdDSAKeyPair.generate;
import static net.java.otr4j.crypto.ed448.EdDSAKeyPair.verify;
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
        assertEquals(expected, generated);
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullMessage() {
        this.keypair.sign(null);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullPublicKey() throws ValidationException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(null, message, sig);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullMessage() throws ValidationException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(this.keypair.getPublicKey(), null, sig);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullSignature() throws ValidationException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        verify(this.keypair.getPublicKey(), message, null);
    }

    @Test
    public void testSignatureIsVerifiable() throws ValidationException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(this.keypair.getPublicKey(), message, sig);
    }

    @Test(expected = ValidationException.class)
    public void testVerifyWrongPublicKey() throws ValidationException {
        final EdDSAKeyPair keypair2 = EdDSAKeyPair.generate(RANDOM);
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(keypair2.getPublicKey(), message, sig);
    }

    @Test(expected = ValidationException.class)
    public void testVerifyWrongMessage() throws ValidationException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        verify(this.keypair.getPublicKey(), "bladkfjsaf".getBytes(UTF_8), sig);
    }

    @Test(expected = ValidationException.class)
    public void testVerifyWrongSignature() throws ValidationException {
        final byte[] message = "SomeRandomMessage".getBytes(UTF_8);
        final byte[] sig = this.keypair.sign(message);
        sig[0] = 0;
        verify(this.keypair.getPublicKey(), message, sig);
    }
}
