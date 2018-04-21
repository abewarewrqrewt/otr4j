package net.java.otr4j.crypto;

import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ECDHKeyPair.generate;
import static nl.dannyvanheumen.joldilocks.Ed448.sign;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings("ConstantConditions")
public class ECDHKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BigInteger sk = new BigInteger("201813413369092340303433879563900627958148970380718420601528361290790948759469372234812322817714647596845093618167700052967566766936416", 10);

    @Test(expected = NullPointerException.class)
    public void testGenerateNullSecureRandom() {
        generate((SecureRandom) null);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateNullBytes() {
        generate((byte[]) null);
    }

    @Test
    public void testGenerateKeyPair() {
        final ECDHKeyPair keypair = generate(RANDOM);
        assertNotNull(keypair);
        assertNotNull(keypair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testSigningNullMessage() {
        ECDHKeyPair.generate(RANDOM).sign(null);
    }

    @Test
    public void testSigningHelloWorldMessage() {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        final byte[] message = "Hello World".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = sign(sk, new byte[0], message);
        final byte[] signature = keypair.sign(message);
        assertArrayEquals(expected, signature);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullPublicKey() throws OtrCryptoException {
        final byte[] message = "Hello World".getBytes(StandardCharsets.US_ASCII);
        final byte[] signature = new byte[]{124, -104, 13, -97, 19, 69, 35, 94, -60, -124, 53, 69, 35, 20, -88, -63, -39, 89, -100, 44, 102, 69, 6, -97, -3, 44, -104, -42, -5, -116, 67, 22, 20, -54, 96, -82, 77, 83, -90, 37, 117, 37, -44, -86, -121, 90, -21, -101, 54, -85, 58, 29, 10, -62, 24, 63, -128, 16, -21, 104, -119, -81, 1, 93, 88, 122, 25, 81, -44, 110, 116, -72, -77, 104, 1, -65, -20, 127, -8, 114, -90, -9, -52, 102, 56, 35, -45, -41, 81, -42, -31, 48, 76, -64, 113, -124, 108, 98, 24, -31, -123, -14, -64, -39, -105, 45, -4, -56, 95, 50, 101, 97, 10, 0};
        ECDHKeyPair.verify(null, message, signature);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullMessage() throws OtrCryptoException {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        final byte[] signature = new byte[]{124, -104, 13, -97, 19, 69, 35, 94, -60, -124, 53, 69, 35, 20, -88, -63, -39, 89, -100, 44, 102, 69, 6, -97, -3, 44, -104, -42, -5, -116, 67, 22, 20, -54, 96, -82, 77, 83, -90, 37, 117, 37, -44, -86, -121, 90, -21, -101, 54, -85, 58, 29, 10, -62, 24, 63, -128, 16, -21, 104, -119, -81, 1, 93, 88, 122, 25, 81, -44, 110, 116, -72, -77, 104, 1, -65, -20, 127, -8, 114, -90, -9, -52, 102, 56, 35, -45, -41, 81, -42, -31, 48, 76, -64, 113, -124, 108, 98, 24, -31, -123, -14, -64, -39, -105, 45, -4, -56, 95, 50, 101, 97, 10, 0};
        ECDHKeyPair.verify(keypair.getPublicKey(), null, signature);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNullSignature() throws OtrCryptoException {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        final byte[] message = "Hello World".getBytes(StandardCharsets.US_ASCII);
        ECDHKeyPair.verify(keypair.getPublicKey(), message, null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyBadSignature() throws OtrCryptoException {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        final byte[] message = "Hello Internet".getBytes(StandardCharsets.US_ASCII);
        final byte[] signature = new byte[]{124, -104, 13, -97, 19, 69, 35, 94, -60, -124, 53, 69, 35, 20, -88, -63, -39, 89, -100, 44, 102, 69, 6, -97, -3, 44, -104, -42, -5, -116, 67, 22, 20, -54, 96, -82, 77, 83, -90, 37, 117, 37, -44, -86, -121, 90, -21, -101, 54, -85, 58, 29, 10, -62, 24, 63, -128, 16, -21, 104, -119, -81, 1, 93, 88, 122, 25, 81, -44, 110, 116, -72, -77, 104, 1, -65, -20, 127, -8, 114, -90, -9, -52, 102, 56, 35, -45, -41, 81, -42, -31, 48, 76, -64, 113, -124, 108, 98, 24, -31, -123, -14, -64, -39, -105, 45, -4, -56, 95, 50, 101, 97, 10, 0};
        ECDHKeyPair.verify(keypair.getPublicKey(), message, signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testVerifySignatureTooShort() throws OtrCryptoException {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        final byte[] message = "Hello World".getBytes(StandardCharsets.US_ASCII);
        final byte[] signature = new byte[]{124, -104, 13, -97, 19, 69, 35, 94, -60, -124, 53, 69, 35, 20, -88, -63, -39, 89, -100, 44, 102, 69, 6, -97, -3, 44, -104, -42, -5, -116, 67, 22, 20, -54, 96, -82, 77, 83, -90, 37, 117, 37, -44, -86, -121, 90, -21, -101, 54, -85, 58, 29, 10, -62, 24, 63, -128, 16, -21, 104, -119, -81, 1, 93, 88, 122, 25, 81, -44, 110, 116, -72, -77, 104, 1, -65, -20, 127, -8, 114, -90, -9, -52, 102, 56, 35, -45, -41, 81, -42, -31, 48, 76, -64, 113, -124, 108, 98, 24, -31, -123, -14, -64, -39, -105, 45, -4, -56, 95, 50, 101, 97, 10};
        ECDHKeyPair.verify(keypair.getPublicKey(), message, signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testVerifySignatureTooLarge() throws OtrCryptoException {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        final byte[] message = "Hello Internet".getBytes(StandardCharsets.US_ASCII);
        final byte[] signature = new byte[]{124, -104, 13, -97, 19, 69, 35, 94, -60, -124, 53, 69, 35, 20, -88, -63, -39, 89, -100, 44, 102, 69, 6, -97, -3, 44, -104, -42, -5, -116, 67, 22, 20, -54, 96, -82, 77, 83, -90, 37, 117, 37, -44, -86, -121, 90, -21, -101, 54, -85, 58, 29, 10, -62, 24, 63, -128, 16, -21, 104, -119, -81, 1, 93, 88, 122, 25, 81, -44, 110, 116, -72, -77, 104, 1, -65, -20, 127, -8, 114, -90, -9, -52, 102, 56, 35, -45, -41, 81, -42, -31, 48, 76, -64, 113, -124, 108, 98, 24, -31, -123, -14, -64, -39, -105, 45, -4, -56, 95, 50, 101, 97, 10, 0, 13};
        ECDHKeyPair.verify(keypair.getPublicKey(), message, signature);
    }
}
