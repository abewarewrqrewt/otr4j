/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import net.java.otr4j.io.OtrOutputStream;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.toHexString;

/**
 * Utility for cryptographic functions.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class OtrCryptoEngine {

    private static final String MD_SHA1 = "SHA-1";
    private static final String MD_SHA256 = "SHA-256";
    private static final String HMAC_SHA1 = "HmacSHA1";
    private static final String HMAC_SHA256 = "HmacSHA256";

    static {
        // Test initialization of all required cryptographic types that need to
        // be created through their respective factories. This test can function
        // as an early indicator in case support for required types is missing.
        try {
            Mac.getInstance(HMAC_SHA256);
            Mac.getInstance(HMAC_SHA1);
            MessageDigest.getInstance(MD_SHA256);
            MessageDigest.getInstance(MD_SHA1);
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Failed initialization test of required cryptographic types. otr4j will not function properly.", ex);
        }
    }

    /**
     * The SHA-256 digest length in bytes.
     */
    public static final int SHA256_DIGEST_LENGTH_BYTES = 32;

    /**
     * Length of MAC in bytes.
     */
    private static final int MAC_LENGTH_BYTES = 20;
    /**
     * The AES key length in bytes.
     */
    public static final int AES_KEY_BYTE_LENGTH = 16;
    private static final int CTR_LENGTH_BYTES = 16;

    private OtrCryptoEngine() {
        // this class is never instantiated, it only has static methods
    }

    /**
     * SHA-256 HMAC calculation.
     *
     * @param b   The input bytes to calculate checksum of.
     * @param key The salt value for the HMAC calculation.
     * @return Returns the HMAC checksum.
     * @throws OtrCryptoException In case of illegal key value.
     */
    @Nonnull
    public static byte[] sha256Hmac(@Nonnull final byte[] b, @Nonnull final byte[] key) throws OtrCryptoException {
        return sha256Hmac(b, key, 0);
    }

    /**
     * SHA-256 HMAC calculation.
     *
     * @param b      The input bytes to calculate checksum of.
     * @param key    The salt value for the HMAC calculation.
     * @param length The length of the resulting checksum.
     * @return Returns the HMAC checksum.
     * @throws OtrCryptoException In case of illegal key value.
     */
    @Nonnull
    private static byte[] sha256Hmac(@Nonnull final byte[] b, @Nonnull final byte[] key, final int length)
            throws OtrCryptoException {
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(key) : "Expected non-zero bytes for key. This may indicate that a critical bug is present, or it may be a false warning.";
        final SecretKeySpec keyspec = new SecretKeySpec(key, HMAC_SHA256);
        final Mac mac;
        try {
            mac = Mac.getInstance(HMAC_SHA256);
            mac.init(keyspec);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to initialize MAC based on SHA-256.", e);
        } catch (final InvalidKeyException e) {
            throw new OtrCryptoException("Invalid key, results in invalid keyspec.", e);
        }

        final byte[] macBytes = mac.doFinal(b);

        if (length > 0) {
            final byte[] bytes = new byte[length];
            final ByteBuffer buff = ByteBuffer.wrap(macBytes);
            buff.get(bytes);
            return bytes;
        } else {
            return macBytes;
        }
    }

    /**
     * The SHA-1 HMAC.
     *
     * @param b   the input bytes
     * @param key the salt
     * @return Returns the checksum.
     */
    @Nonnull
    public static byte[] sha1Hmac(@Nonnull final byte[] b, @Nonnull final byte[] key) {
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(key) : "Expected non-zero bytes for key. This may indicate that a critical bug is present, or it may be a false warning.";
        final byte[] macBytes;
        try {
            final Mac mac = Mac.getInstance(HMAC_SHA1);
            mac.init(new SecretKeySpec(key, HMAC_SHA1));
            macBytes = mac.doFinal(b);
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Unsupported HMAC function specified.", ex);
        } catch (final InvalidKeyException ex) {
            throw new IllegalStateException("Invalid key, results in invalid keyspec.", ex);
        }
        final byte[] bytes = new byte[MAC_LENGTH_BYTES];
        ByteBuffer.wrap(macBytes).get(bytes);
        return bytes;
    }

    /**
     * SHA-256 HMAC, take first 160 bits (20 bytes).
     *
     * @param b   the bytes
     * @param key the salt
     * @return Returns the checksum result.
     * @throws OtrCryptoException In case of illegal key value.
     */
    @Nonnull
    public static byte[] sha256Hmac160(@Nonnull final byte[] b, @Nonnull final byte[] key) throws OtrCryptoException {
        return sha256Hmac(b, key, MAC_LENGTH_BYTES);
    }

    /**
     * SHA-256 hash function.
     *
     * @param first the first bytes
     * @param next  any possible next byte-arrays of additional data
     * @return Returns the checksum result.
     */
    @Nonnull
    public static byte[] sha256Hash(@Nonnull final byte[] first, final byte[]... next) {
        final MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance(MD_SHA256);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to acquire SHA-256 message digest.", e);
        }
        sha256.update(first);
        for (final byte[] b : next) {
            sha256.update(b, 0, b.length);
        }
        return sha256.digest();
    }

    /**
     * SHA-1 hash function.
     *
     * @param first the first bytes
     * @param next  any possible next byte-arrays of additional data
     * @return Returns the checksum result.
     */
    @Nonnull
    public static byte[] sha1Hash(@Nonnull final byte[] first, final byte[]... next) {
        final MessageDigest sha1;
        try {
            sha1 = MessageDigest.getInstance(MD_SHA1);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to acquire SHA1 message digest.", e);
        }
        sha1.update(first, 0, first.length);
        for (final byte[] b : next) {
            sha1.update(b, 0, b.length);
        }
        return sha1.digest();
    }

    /**
     * Decrypt AES-encrypted payload.
     *
     * @param key the decryption key
     * @param ctr the counter value used in encryption
     * @param b   the ciphertext
     * @return Returns the decrypted content.
     * @throws OtrCryptoException In case of illegal ciphertext.
     */
    @Nonnull
    public static byte[] aesDecrypt(@Nonnull final byte[] key, @Nullable final byte[] ctr, @Nonnull final byte[] b)
            throws OtrCryptoException {
        assert !allZeroBytes(key) : "Expected non-zero bytes for key. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        final AESEngine aesDec = new AESEngine();
        final SICBlockCipher sicAesDec = new SICBlockCipher(aesDec);
        final BufferedBlockCipher bufSicAesDec = new BufferedBlockCipher(sicAesDec);

        // Either use existing ctr or create initial counter value 0.
        final byte[] iv = ctr == null ? new byte[CTR_LENGTH_BYTES] : ctr;
        bufSicAesDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        final byte[] aesOutLwDec = new byte[b.length];
        final int done = bufSicAesDec.processBytes(b, 0, b.length, aesOutLwDec, 0);
        try {
            bufSicAesDec.doFinal(aesOutLwDec, done);
        } catch (final InvalidCipherTextException ex) {
            throw new OtrCryptoException("Encrypted message contents is bad.", ex);
        }

        return aesOutLwDec;
    }

    /**
     * Encrypt payload using AES.
     *
     * @param key the encryption key
     * @param ctr the counter value to use
     * @param b   the plaintext content in bytes
     * @return Returns the encrypted content.
     */
    @Nonnull
    public static byte[] aesEncrypt(@Nonnull final byte[] key, @Nullable final byte[] ctr, @Nonnull final byte[] b) {
        assert !allZeroBytes(key) : "Expected non-zero bytes for key. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        final AESEngine aesEnc = new AESEngine();
        final SICBlockCipher sicAesEnc = new SICBlockCipher(aesEnc);
        final BufferedBlockCipher bufSicAesEnc = new BufferedBlockCipher(sicAesEnc);

        // Create initial counter value 0.
        final byte[] iv = ctr == null ? new byte[CTR_LENGTH_BYTES] : ctr;
        bufSicAesEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        final byte[] aesOutLwEnc = new byte[b.length];
        final int done = bufSicAesEnc.processBytes(b, 0, b.length, aesOutLwEnc, 0);
        try {
            bufSicAesEnc.doFinal(aesOutLwEnc, done);
        } catch (final InvalidCipherTextException ex) {
            throw new IllegalStateException("Failed to encrypt content.", ex);
        }
        return aesOutLwEnc;
    }

    /**
     * Get the fingerprint for provided DSA public key.
     *
     * @param pubKey the DSA public key
     * @return Returns fingerprint in hexadecimal string-representation
     */
    @Nonnull
    public static String getFingerprint(@Nonnull final DSAPublicKey pubKey) {
        final byte[] b = getFingerprintRaw(pubKey);
        return toHexString(b);
    }

    /**
     * Get the fingerprint for provided DSA public key as "raw" byte-array.
     *
     * @param pubKey the DSA public key
     * @return Returns the fingerprint as byte-array.
     */
    @Nonnull
    public static byte[] getFingerprintRaw(@Nonnull final DSAPublicKey pubKey) {
        final byte[] bRemotePubKey = new OtrOutputStream().writePublicKey(pubKey).toByteArray();
        final byte[] trimmed = new byte[bRemotePubKey.length - 2];
        System.arraycopy(bRemotePubKey, 2, trimmed, 0, trimmed.length);
        return sha1Hash(trimmed);
    }

    /**
     * Equality check for byte arrays that throws an exception in case of
     * failure. This version enables us to put equality checks in line with
     * other code and be sure that we immediately "exit" upon failing a check,
     * hence we cannot forget to handle the verification result.
     *
     * @param a byte[] a
     * @param b byte[] b
     * @param message The exception message in case of arrays are not equal.
     * @throws OtrCryptoException Throws exception in case of inequality.
     */
    public static void checkEquals(@Nonnull final byte[] a, @Nonnull final byte[] b, @Nonnull final String message)
            throws OtrCryptoException {
        assert !allZeroBytes(a) : "Expected non-zero bytes for a. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        if (!constantTimeEquals(a, b)) {
            throw new OtrCryptoException(message);
        }
    }
}
