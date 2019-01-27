/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FINGERPRINT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decodePoint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine4.encrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateNonce;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.identity;
import static net.java.otr4j.crypto.ed448.PointTestUtils.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;

@SuppressWarnings({"ConstantConditions"})
public class OtrCryptoEngine4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BigInteger MINUSONE = BigInteger.valueOf(-1L);

    private final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
    private final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
    private final ECDHKeyPair ephemeralKeyPair = ECDHKeyPair.generate(RANDOM);

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullPoint() {
        fingerprint(null);
    }

    @Test
    public void testFingerprint() {
        final byte[] expected = new byte[] {50, -88, 40, -102, 20, -109, -8, 68, 71, 76, -23, -19, -66, -56, 94, 17, 27, -12, -68, -66, -49, -5, -62, -18, -79, 54, -80, 122, 121, 39, 10, 70, -63, 83, -60, -121, 51, 35, 124, -116, -68, 92, 100, 64, -47, 113, 38, 117, -75, 111, 74, 5, -6, 14, -91, 118};
        final byte[] dst = fingerprint(basePoint());
        assertArrayEquals(expected, dst);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullDestination() {
        final byte[] input = "someinput".getBytes(US_ASCII);
        kdf1(null, 0, FINGERPRINT, input, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullKDFUsage() {
        final byte[] dst = new byte[100];
        kdf1(dst, 0, null, new byte[] {(byte) 0xff}, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullInput() {
        final byte[] dst = new byte[100];
        kdf1(dst, 0, FINGERPRINT, null, 32);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf1(new byte[1], 0, FINGERPRINT, input, 32);
    }

    @Test
    public void testKdf1DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {51, 79, -93, 96, 82, -80, -50, 81, 65, 106, -39, -43, 79, 58, 69, -26, -73, -52, -110, -48, -110, -66, -23, -26, 76, -43, 65, 120, 52, -65, -71, -50, 0};
        final byte[] dst = new byte[32 + 1];
        kdf1(dst, 0, FINGERPRINT, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 51, 79, -93, 96, 82, -80, -50, 81, 65, 106, -39, -43, 79, 58, 69, -26, -73, -52, -110, -48, -110, -66, -23, -26, 76, -43, 65, 120, 52, -65, -71, -50};
        final byte[] dst = new byte[32 + 1];
        kdf1(dst, 1, FINGERPRINT, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {51, 79, -93, 96, 82, -80, -50, 81, 65, 106, -39, -43, 79, 58, 69, -26, -73, -52, -110, -48, -110, -66, -23, -26, 76, -43, 65, 120, 52, -65, -71, -50};
        final byte[] dst = new byte[32];
        kdf1(dst, 0, FINGERPRINT, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKdf1NegativeOutputSize() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf1(dst, 0, FINGERPRINT, input, -1);
    }

    @Test
    public void testKdf1ReturnValue() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[32];
        kdf1(expected, 0, FINGERPRINT, input, 32);
        assertArrayEquals(expected, kdf1(FINGERPRINT, input, 32));
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1ReturnValueNullUsageID() {
        kdf1(null, new byte[] {1}, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1ReturnValueNullInput() {
        kdf1(FINGERPRINT, null, 32);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKdf1ReturnValueBadOutputSize() {
        kdf1(FINGERPRINT, "helloworld".getBytes(US_ASCII), -1);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf1(dst, 1, FINGERPRINT, input, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullKDFUsage() {
        hashToScalar(null, new byte[] {1});
    }

    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullBytes() {
        hashToScalar(FINGERPRINT, null);
    }

    @Test
    public void testHashToScalar() {
        final Scalar expected = decodeScalar(new byte[] {105, 16, -83, 85, -9, -62, -46, -92, 7, -23, 67, 50, -59, 94, -15, 91, -59, -120, -64, -43, -77, 27, 44, 3, -94, -23, 33, 64, 125, -65, -71, -50, -103, -100, 31, 100, -19, 85, 74, -13, 2, 94, -128, 70, -12, -52, 46, 126, 49, 105, 43, -65, 56, -50, -41, 33, 0});
        final Scalar actual = hashToScalar(FINGERPRINT, "helloworld".getBytes(US_ASCII));
        assertEquals(expected, actual);
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
        verifyEdDSAPublicKey(identity());
    }

    @Test
    public void testVerifyEdDSAPublicKeyLegit() throws OtrCryptoException {
        EdDSAKeyPair keypair = EdDSAKeyPair.generate(RANDOM);
        verifyEdDSAPublicKey(keypair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullKey() {
        final byte[] nonce = generateNonce(RANDOM);
        encrypt(null, nonce, new byte[1]);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullIV() {
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        encrypt(key, null, new byte[1]);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullMessage() {
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] nonce = generateNonce(RANDOM);
        encrypt(key, nonce, null);
    }

    @Test
    public void testEncryptMessage() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] nonce = generateNonce(RANDOM);
        final byte[] ciphertext = encrypt(key, nonce, message);
        assertNotNull(ciphertext);
        assertFalse(Arrays.equals(message, ciphertext));
    }

    @Test
    public void testEncryptionAndDecryption() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[24];
        RANDOM.nextBytes(iv);
        final byte[] result = decrypt(key, iv, encrypt(key, iv, message));
        assertArrayEquals(message, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptInvalidKeySize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[31];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[24];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptInvalidIVSize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[23];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptInvalidKeySize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[31];
        RANDOM.nextBytes(key);
        final byte[] iv = new byte[24];
        RANDOM.nextBytes(iv);
        encrypt(key, iv, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptInvalidIVSize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
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
        final Point point = decodePoint(ephemeralKeyPair.getPublicKey().encode());
        assertEquals(ephemeralKeyPair.getPublicKey(), point);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullRandom() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(null, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullKeypair() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, null, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullA1() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, null, longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullA2() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullA3() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), null, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignIllegalA1() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point illegal = createPoint(MINUSONE, MINUSONE);
        ringSign(RANDOM, longTermKeyPairB, illegal, longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignIllegalA2() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point illegal = createPoint(MINUSONE, MINUSONE);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), illegal, ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignIllegalA3() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point illegal = createPoint(MINUSONE, MINUSONE);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), illegal, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullMessage() {
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignKeyPairNotPresentInPublicKeys() {
        final EdDSAKeyPair longTermKeyPairA2 = EdDSAKeyPair.generate(RANDOM);
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA2.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullA1() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(null, longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), sigma, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullA2() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairA.getPublicKey(), null, ephemeralKeyPair.getPublicKey(), sigma, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullA3() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), null, sigma, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullSigma() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullMessage() throws OtrCryptoException {
        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeral, message);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeral, sigma, null);
    }

    @Test
    public void testRingSigningWithA1() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                sigma, message);
    }

    @Test
    public void testRingSigningWithA2() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
                longTermKeyPairA.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                sigma, message);
    }

    @Test
    public void testRingSigningWithA3() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), longTermKeyPairA.getPublicKey(), message);
        ringVerify(longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), longTermKeyPairA.getPublicKey(),
                sigma, message);
    }

    @Test(expected = OtrCryptoException.class)
    public void testRingSignDifferentMessage() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        final byte[] wrongMessage = "hello World".getBytes(UTF_8);
        ringVerify(longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                sigma, wrongMessage);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateNonceNullSecureRandom() {
        generateNonce(null);
    }

    @Test
    public void testGenerateNonce() {
        final byte[] result = generateNonce(RANDOM);
        assertNotNull(result);
        requireLengthExactly(24, result);
    }

    @Test
    public void testGenerateNonceIsDifferentEachCall() {
        final byte[] nonce1 = generateNonce(RANDOM);
        final byte[] nonce2 = generateNonce(RANDOM);
        assertNotSame(nonce1, nonce2);
        // In theory this could end up with exactly the same random value. In practice the chance should be so remove
        // that it makes sense to test this.
        assertFalse(Arrays.equals(nonce1, nonce2));
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateRandomValueInZqNullSecureRandom() {
        generateRandomValueInZq(null);
    }

    @Ignore("There is a FIXME to investigate whether this is necessary. I believe it isn't.")
    @Test
    public void testGenerateRandomValueInZq() {
        final Scalar value = generateRandomValueInZq(RANDOM);
        final byte[] bytes = value.encode();
        assertEquals(0, bytes[0] & 0b00000011);
        assertEquals(0b10000000, bytes[55] & 0b10000000);
        assertEquals(0, bytes[56]);
    }

    @Test
    public void testGenerateRandomValueInZqNoThreeAreTheSame() {
        final Scalar v1 = generateRandomValueInZq(RANDOM);
        final Scalar v2 = generateRandomValueInZq(RANDOM);
        final Scalar v3 = generateRandomValueInZq(RANDOM);
        assertNotEquals(v1, v2);
        assertNotEquals(v2, v3);
        assertNotEquals(v1, v3);
    }
}
