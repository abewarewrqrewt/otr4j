package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.FINGERPRINT_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decodePoint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine4.encrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.io.SerializationUtils.UTF8;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Points.identity;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings("ConstantConditions")
public class OtrCryptoEngine4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullDestination() {
        fingerprint(null, identity());
    }

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullPoint() {
        fingerprint(new byte[FINGERPRINT_LENGTH_BYTES], null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testFingerprintDestinationZeroSize() {
        fingerprint(new byte[0], identity());
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testFingerprintDestinationTooSmall() {
        fingerprint(new byte[55], identity());
    }

    @Test
    public void testFingerprintDestinationTooLarge() {
        final byte[] expected = new byte[]{-69, -21, 118, -79, 110, -32, -77, -4, 19, -103, -110, -55, 46, -56, 30, -71, -32, -2, 49, -100, -45, 81, -94, -49, 116, 95, 61, 12, 72, 57, 100, 112, -7, -82, -18, 111, 107, 99, 16, -94, -57, -100, -126, -114, 117, -89, 24, -10, 67, 22, -96, -57, -103, 73, -128, 31, 0};
        final byte[] dst = new byte[57];
        fingerprint(dst, basePoint());
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testFingerprint() {
        final byte[] expected = new byte[]{-69, -21, 118, -79, 110, -32, -77, -4, 19, -103, -110, -55, 46, -56, 30, -71, -32, -2, 49, -100, -45, 81, -94, -49, 116, 95, 61, 12, 72, 57, 100, 112, -7, -82, -18, 111, 107, 99, 16, -94, -57, -100, -126, -114, 117, -89, 24, -10, 67, 22, -96, -57, -103, 73, -128, 31};
        final byte[] dst = new byte[FINGERPRINT_LENGTH_BYTES];
        fingerprint(dst, basePoint());
        assertArrayEquals(expected, dst);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullDestination() {
        final byte[] input = "someinput".getBytes(US_ASCII);
        kdf1(null, 0, input, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullInput() {
        final byte[] dst = new byte[100];
        kdf1(dst, 0, null, 32);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf1(new byte[1], 0, input, 32);
    }

    @Test
    public void testKdf1DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 0};
        final byte[] dst = new byte[32 + 1];
        kdf1(dst, 0, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[32 + 1];
        kdf1(dst, 1, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[32];
        kdf1(dst, 0, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKdf1NegativeOutputSize() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf1(dst, 0, input, -1);
    }

    @Test
    public void testKdf1ReturnValue() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[32];
        kdf1(expected, 0, input, 32);
        assertArrayEquals(expected, kdf1(input, 32));
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1ReturnValueNullInput() {
        kdf1(null, 32);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKdf1ReturnValueBadOutputSize() {
        kdf1("helloworld".getBytes(US_ASCII), -1);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf1(dst, 1, input, 32);
    }


    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullBytes() {
        hashToScalar(null);
    }

    @Test
    public void testHashToScalar() {
        final BigInteger expected = new BigInteger("140888660286710823522416977182523334012318579212723175722386145079376311038285857705111942117343322765056189818196599612200095406328505", 10);
        assertEquals(expected, hashToScalar("helloworld".getBytes(US_ASCII)));
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateEdDSAKeyPairNull() {
        EdDSAKeyPair.generate(null);
    }

    @Test
    public void testGenerateEdDSAKeyPair() {
        assertNotNull(EdDSAKeyPair.generate(RANDOM));
    }

    @Ignore("This test is most likely correct and verification is missing logic. Disabled for now for further research.")
    @Test(expected = OtrCryptoException.class)
    public void testVerifyEdDSAPublicKeyOne() throws OtrCryptoException {
        verifyEdDSAPublicKey(Points.identity());
    }

    @Test
    public void testVerifyEdDSAPublicKeyLegit() throws OtrCryptoException {
        EdDSAKeyPair keypair = EdDSAKeyPair.generate(RANDOM);
        verifyEdDSAPublicKey(keypair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullKey() {
        encrypt(null, new byte[24], new byte[1]);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullIV() {
        encrypt(new byte[24], null, new byte[1]);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullMessage() {
        encrypt(new byte[24], new byte[24], null);
    }

    @Test
    public void testEncryptMessage() {
        final byte[] message = "hello world".getBytes(UTF8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] ciphertext = encrypt(key, new byte[24], message);
        assertNotNull(ciphertext);
        assertFalse(Arrays.equals(message, ciphertext));
    }

    @Test
    public void testEncryptionAndDecryption() {
        final byte[] message = "hello, do the salsa".getBytes(UTF8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[24];
        RANDOM.nextBytes(iv);
        final byte[] result = decrypt(key, iv, encrypt(key, iv, message));
        assertArrayEquals(message, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptInvalidKeySize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF8);
        final byte[] key = new byte[31];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[24];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptInvalidIVSize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[23];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptInvalidKeySize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF8);
        final byte[] key = new byte[31];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[24];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptInvalidIVSize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[23];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = NullPointerException.class)
    public void testDecodePointNull() throws OtrCryptoException {
        decodePoint(null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testDecodePointInvalidLengthLow() throws OtrCryptoException {
        decodePoint(new byte[56]);
    }

    @Test(expected = OtrCryptoException.class)
    public void testDecodePointInvalidLengthHigh() throws OtrCryptoException {
        decodePoint(new byte[58]);
    }

    @Test
    public void testDecodePoint() throws OtrCryptoException {
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        final Point point = decodePoint(keypair.getPublicKey().encode());
        assertEquals(keypair.getPublicKey().x(), point.x());
        assertEquals(keypair.getPublicKey().y(), point.y());
    }

//    @Test(expected = NullPointerException.class)
//    public void testRingSignNullRandom() {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final byte[] message = "hello world".getBytes(UTF_8);
//        ringSign(null, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeral,
//            message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingSignNullKeypair() {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final byte[] message = "hello world".getBytes(UTF_8);
//        ringSign(RANDOM, null, longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeral, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingSignNullA1() {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final byte[] message = "hello world".getBytes(UTF_8);
//        ringSign(RANDOM, longTermKeyPairA, null, longTermKeyPairA.getPublicKey(), ephemeral, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingSignNullA2() {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final byte[] message = "hello world".getBytes(UTF_8);
//        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), null, ephemeral, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingSignNullA3() {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), null, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingSignNullMessage() {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeral, null);
//    }
//
//    @Test(expected = IllegalArgumentException.class)
//    public void testRingSignKeyPairNotPresentInPublicKeys() {
//        final EdDSAKeyPair longTermKeyPairA1 = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairA2 = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        ringSign(RANDOM, longTermKeyPairA1, longTermKeyPairB.getPublicKey(), longTermKeyPairA2.getPublicKey(), ephemeral, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingVerifyNullA1() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
//            longTermKeyPairB.getPublicKey(), ephemeral, message);
//        ringVerify(null, longTermKeyPairB.getPublicKey(), ephemeral, sigma, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingVerifyNullA2() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
//            longTermKeyPairB.getPublicKey(), ephemeral, message);
//        ringVerify(longTermKeyPairA.getPublicKey(), null, ephemeral, sigma, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingVerifyNullA3() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
//            longTermKeyPairB.getPublicKey(), ephemeral, message);
//        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), null, sigma, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingVerifyNullSigma() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeral, null, message);
//    }
//
//    @Test(expected = NullPointerException.class)
//    public void testRingVerifyNullMessage() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
//            longTermKeyPairB.getPublicKey(), ephemeral, message);
//        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeral, sigma, null);
//    }
//
//    @Test
//    public void testRingSigningWithA1() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
//            longTermKeyPairB.getPublicKey(), ephemeral, message);
//        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeral, sigma, message);
//    }
//
//    @Test
//    public void testRingSigningWithA2() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
//            longTermKeyPairA.getPublicKey(), ephemeral, message);
//        ringVerify(longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeral, sigma, message);
//    }
//
//    @Test
//    public void testRingSigningWithA3() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
//            ephemeral, longTermKeyPairA.getPublicKey(), message);
//        ringVerify(longTermKeyPairB.getPublicKey(), ephemeral, longTermKeyPairA.getPublicKey(), sigma, message);
//    }
//
//    @Test(expected = OtrCryptoException.class)
//    public void testRingSignDifferentMessage() throws OtrCryptoException {
//        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
//        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
//        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
//        final byte[] message = "hello world".getBytes(UTF_8);
//        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
//            longTermKeyPairA.getPublicKey(), ephemeral, message);
//        final byte[] wrongMessage = "hello World".getBytes(UTF_8);
//        ringVerify(longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeral, sigma, wrongMessage);
//    }
}
