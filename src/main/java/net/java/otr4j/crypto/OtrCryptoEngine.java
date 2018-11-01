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
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.signers.DSASigner;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.ByteArrays.toHexString;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * Utility for cryptographic functions.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class OtrCryptoEngine {

    private static final String ALGORITHM_DSA = "DSA";
    private static final String MD_SHA1 = "SHA-1";
    private static final String MD_SHA256 = "SHA-256";
    private static final String HMAC_SHA1 = "HmacSHA1";
    private static final String HMAC_SHA256 = "HmacSHA256";

    static {
        // Test initialization of all required cryptographic types that need to
        // be created through their respective factories. This test can function
        // as an early indicator in case support for required types is missing.
        try {
            KeyPairGenerator.getInstance(ALGORITHM_DSA);
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
     * Generate a DSA key pair.
     *
     * @return Returns the DSA key pair.
     */
    // FIXME move 'generateDSAKeyPair' into DSAKeyPair class similar to how it is implemented in EdDSAKeyPair.
    @Nonnull
    public static DSAKeyPair generateDSAKeyPair() {
        try {
            final KeyPairGenerator kg = KeyPairGenerator.getInstance(ALGORITHM_DSA);
            final java.security.KeyPair keypair = kg.genKeyPair();
            return new DSAKeyPair((DSAPrivateKey) keypair.getPrivate(), (DSAPublicKey) keypair.getPublic());
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to generate DSA key pair.", e);
        }
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
     * @throws OtrCryptoException In case of illegal key value.
     */
    @Nonnull
    public static byte[] sha1Hmac(@Nonnull final byte[] b, @Nonnull final byte[] key) throws OtrCryptoException {
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
            throw new OtrCryptoException("Invalid key, results in invalid keyspec.", ex);
        }
        // TODO verify if we need to take x bytes from the total package. Most likely HMAC_SHA1 already produces a 20-byte result.
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
     * @throws OtrCryptoException In case of failure to encrypt content.
     */
    @Nonnull
    public static byte[] aesEncrypt(@Nonnull final byte[] key, @Nullable final byte[] ctr, @Nonnull final byte[] b)
            throws OtrCryptoException {
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
            throw new OtrCryptoException("Failed to encrypt content.", ex);
        }
        return aesOutLwEnc;
    }

    /**
     * Sign bytes with provided private key.
     *
     * @param b          the source content
     * @param privatekey the DSA private key
     * @return Returns signature in bytes.
     */
    @Nonnull
    public static byte[] sign(@Nonnull final byte[] b, @Nonnull final DSAPrivateKey privatekey) {
        final BigInteger q = privatekey.getParams().getQ();
        final DSASignature signature = signRS(b, privatekey);

        final int siglen = q.bitLength() / 4;
        final int rslen = siglen / 2;
        final byte[] rb = asUnsignedByteArray(signature.r);
        final byte[] sb = asUnsignedByteArray(signature.s);

        // Create the final signature array, padded with zeros if necessary.
        final byte[] sig = new byte[siglen];
        System.arraycopy(rb, 0, sig, rslen - rb.length, rb.length);
        System.arraycopy(sb, 0, sig, sig.length - sb.length, sb.length);
        return sig;
    }

    /**
     * Sign data 'b' using DSA private key 'privateKey' and return signature components 'r' and 's'.
     *
     * @param b          The data to be signed.
     * @param privateKey The private key.
     * @return Signature components 'r' and 's'.
     */
    @Nonnull
    public static DSASignature signRS(@Nonnull final byte[] b, @Nonnull final DSAPrivateKey privateKey) {
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        final DSAParams dsaParams = privateKey.getParams();
        final DSAParameters bcDSAParameters = new DSAParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
        final DSAPrivateKeyParameters bcDSAPrivateKeyParms = new DSAPrivateKeyParameters(privateKey.getX(),
                bcDSAParameters);

        final DSASigner dsaSigner = new DSASigner();
        dsaSigner.init(true, bcDSAPrivateKeyParms);

        final BigInteger q = dsaParams.getQ();

        // Ian: Note that if you can get the standard DSA implementation you're
        // using to not hash its input, you should be able to pass it ((256-bit
        // value) mod q), (rather than truncating the 256-bit value) and all
        // should be well.
        // ref: Interop problems with libotr - DSA signature
        final BigInteger bmpi = new BigInteger(1, b);
        final BigInteger[] signature = dsaSigner.generateSignature(asUnsignedByteArray(bmpi.mod(q)));
        assert signature.length == 2 : "signRS result does not contain the expected 2 components: r and s";
        return new DSASignature(signature[0], signature[1]);
    }

    /**
     * A type representing the DSA signature in its two individual components.
     */
    public static final class DSASignature {

        /**
         * The 'r' component.
         */
        public final BigInteger r;
        /**
         * The 's' component.
         */
        public final BigInteger s;

        /**
         * The DSA signature constructor.
         *
         * @param r the 'r' component
         * @param s the 's' component
         */
        public DSASignature(@Nonnull final BigInteger r, @Nonnull final BigInteger s) {
            this.r = requireNonNull(r);
            this.s = requireNonNull(s);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final DSASignature that = (DSASignature) o;
            // TODO should this be constant-time?
            return Objects.equals(r, that.r) && Objects.equals(s, that.s);
        }

        @Override
        public int hashCode() {
            return Objects.hash(r, s);
        }
    }

    /**
     * Verify DSA signature against expectation using provided DSA public key
     * instance..
     *
     * @param b data expected to be signed.
     * @param pubKey Public key. Provided public key must be an instance of
     * DSAPublicKey.
     * @param rs Components R and S.
     * @throws OtrCryptoException Thrown in case of failed verification.
     */
    public static void verify(@Nonnull final byte[] b, @Nonnull final DSAPublicKey pubKey, @Nonnull final byte[] rs)
            throws OtrCryptoException {
        final int qlen = pubKey.getParams().getQ().bitLength() / 8;
        requireLengthExactly(2 * qlen, rs);
        final ByteBuffer buff = ByteBuffer.wrap(rs);
        final byte[] r = new byte[qlen];
        buff.get(r);
        final byte[] s = new byte[qlen];
        buff.get(s);
        verify(b, pubKey, r, s);
    }

    private static void verify(@Nonnull final byte[] b, @Nonnull final DSAPublicKey pubKey, @Nonnull final byte[] r,
            @Nonnull final byte[] s) throws OtrCryptoException {
        assert !allZeroBytes(r) : "Expected non-zero bytes for r. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(s) : "Expected non-zero bytes for s. This may indicate that a critical bug is present, or it may be a false warning.";
        verify(b, pubKey, new BigInteger(1, r), new BigInteger(1, s));
    }

    /**
     * Verify a message using a signature represented as two MPI components: 'r' and 's'.
     *
     * @param b      the message in bytes
     * @param pubKey the DSA public key
     * @param r      the signature component 'r'
     * @param s      the signature component 's'
     * @throws OtrCryptoException In case of illegal signature.
     */
    public static void verify(@Nonnull final byte[] b, @Nonnull final DSAPublicKey pubKey, @Nonnull final BigInteger r,
            @Nonnull final BigInteger s) throws OtrCryptoException {
        requireNonNull(b);
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        final DSAParams dsaParams = pubKey.getParams();
        final BigInteger q = dsaParams.getQ();
        final DSAParameters bcDSAParams = new DSAParameters(dsaParams.getP(), q, dsaParams.getG());
        final DSAPublicKeyParameters dsaPubParams;
        try {
            dsaPubParams = new DSAPublicKeyParameters(pubKey.getY(), bcDSAParams);
        } catch (final IllegalArgumentException e) {
            throw new OtrCryptoException("Illegal parameters provided for DSA public key parameters.", e);
        }

        // Ian: Note that if you can get the standard DSA implementation you're
        // using to not hash its input, you should be able to pass it ((256-bit
        // value) mod q), (rather than truncating the 256-bit value) and all
        // should be well.
        // ref: Interop problems with libotr - DSA signature
        final DSASigner dsaSigner = new DSASigner();
        dsaSigner.init(false, dsaPubParams);

        final BigInteger bmpi = new BigInteger(1, b);
        if (!dsaSigner.verifySignature(asUnsignedByteArray(bmpi.mod(q)), r, s)) {
            throw new OtrCryptoException("DSA signature verification failed.");
        }
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

    /**
     * (Re)Create DSA public key based on provided input parameters.
     *
     * @param y y
     * @param p p
     * @param q q
     * @param g g
     * @return Returns DSA public key.
     * @throws OtrCryptoException Throws OtrCryptoException in case of failure to create DSA public key.
     */
    @Nonnull
    public static DSAPublicKey createDSAPublicKey(@Nonnull final BigInteger y, @Nonnull final BigInteger p,
            @Nonnull final BigInteger q, @Nonnull final BigInteger g)
            throws OtrCryptoException {
        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("DSA");
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to initialize DSA key factory.", e);
        }
        try {
            final DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
            return (DSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (final InvalidKeySpecException e) {
            throw new OtrCryptoException("Read invalid public key from input stream.", e);
        }
    }
}
