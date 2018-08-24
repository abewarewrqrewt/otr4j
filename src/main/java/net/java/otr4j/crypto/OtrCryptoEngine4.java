package net.java.otr4j.crypto;

import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;
import nl.dannyvanheumen.joldilocks.Points;
import nl.dannyvanheumen.joldilocks.Points.InvalidDataException;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;

import static java.math.BigInteger.ZERO;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FINGERPRINT;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.Integers.requireAtLeast;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;
import static nl.dannyvanheumen.joldilocks.Scalars.encodeLittleEndianTo;
import static org.bouncycastle.util.Arrays.clear;

/**
 * Crypto engine for OTRv4.
 */
// FIXME what do we need to do to correctly use the "COFACTOR" component of Ed448? (No special attention paid to this so far.)
public final class OtrCryptoEngine4 {

    /**
     * Bit-size for SHAKE-256.
     */
    private static final int SHAKE_256_LENGTH_BITS = 256;

    /**
     * Length of a fingerprint in bytes.
     */
    private static final int FINGERPRINT_LENGTH_BYTES = 56;

    /**
     * Length of HashToScalar array of bytes.
     */
    private static final int HASH_TO_SCALAR_LENGTH_BYTES = 64;

    /**
     * Prefix used in key derivation functions.
     */
    private static final byte[] OTR4_PREFIX = new byte[]{'O', 'T', 'R', 'v', '4'};

    /**
     * Size of IV for XSalsa20.
     */
    private static final int XSALSA20_IV_LENGTH_BYTES = 24;

    /**
     * KDF Usage IDs.
     */
    public enum KDFUsage {
        /**
         * Usage ID for Fingerprint.
         */
        FINGERPRINT((byte) 0x00),
        /**
         * Usage ID for Brace Key generation on every third iteration.
         */
        THIRD_BRACE_KEY((byte) 0x01),
        /**
         * Usage ID for Brace Key generation on other iterations.
         */
        BRACE_KEY((byte) 0x02),
        /**
         * Usage ID for shared secret.
         */
        SHARED_SECRET((byte) 0x03),
        /**
         * Usage ID for SSID.
         */
        SSID((byte) 0x04),
        /**
         * Usage ID for Bob's client profile used in Auth-R message.
         */
        AUTH_R_BOB_CLIENT_PROFILE((byte) 0x05),
        /**
         * Usage ID for Alice's client profile used in Auth-R message.
         */
        AUTH_R_ALICE_CLIENT_PROFILE((byte) 0x06),
        /**
         * Usage ID for Phi in Auth-R message.
         */
        AUTH_R_PHI((byte) 0x07),
        /**
         * Usage ID for Bob's client profile used in Auth-I message.
         */
        AUTH_I_BOB_CLIENT_PROFILE((byte) 0x08),
        /**
         * Usage ID for Alice's client profile used in Auth-I message.
         */
        AUTH_I_ALICE_CLIENT_PROFILE((byte) 0x09),
        /**
         * Usage ID for Phi in Auth-I message.
         */
        AUTH_I_PHI((byte) 0x0A),
        /**
         * Usage ID for generating the first ephemeral ECDH key, to initialize the Double Ratchet.
         */
        ECDH_FIRST_EPHEMERAL((byte) 0x11),
        /**
         * Usage ID for generating the first ephemeral DH key, to initialize the Double Ratchet.
         */
        DH_FIRST_EPHEMERAL((byte) 0x12),
        /**
         * Usage ID for generating a root key.
         */
        ROOT_KEY((byte) 0x13),
        /**
         * Usage ID for generating a chain key.
         */
        CHAIN_KEY((byte) 0x14),
        /**
         * Usage ID for generating the next chain key.
         */
        NEXT_CHAIN_KEY((byte) 0x15),
        /**
         * Usage ID for generating a message key.
         */
        MESSAGE_KEY((byte) 0x16),
        /**
         * Usage ID for generating a MAC key.
         */
        MAC_KEY((byte) 0x17),
        /**
         * Usage ID for generating the Extra Symmetric Key.
         */
        EXTRA_SYMMETRIC_KEY((byte) 0x18),
        /**
         * Usage ID for generating the hash for the Data Message sections.
         */
        DATA_MESSAGE_SECTIONS((byte) 0x19),
        /**
         * Usage ID for generating the Authenticator MAC value.
         */
        AUTHENTICATOR((byte) 0x1A),
        /**
         * Usage ID for generating the secret used in the SMP negotiation.
         */
        SMP_SECRET((byte) 0x1B),
        /**
         * Usage ID for generating the authentication code for the ring signatures.
         */
        AUTH((byte) 0x1C),
        /**
         * Usage ID for SMP value 0x01.
         */
        SMP_VALUE_0x01((byte) 0x01),
        /**
         * Usage ID for SMP value 0x02.
         */
        SMP_VALUE_0x02((byte) 0x02),
        /**
         * Usage ID for SMP value 0x03.
         */
        SMP_VALUE_0x03((byte) 0x03),
        /**
         * Usage ID for SMP value 0x04.
         */
        SMP_VALUE_0x04((byte) 0x04),
        /**
         * Usage ID for SMP value 0x05.
         */
        SMP_VALUE_0x05((byte) 0x05),
        /**
         * Usage ID for SMP value 0x06.
         */
        SMP_VALUE_0x06((byte) 0x06),
        /**
         * Usage ID for SMP value 0x07.
         */
        SMP_VALUE_0x07((byte) 0x07),
        /**
         * Usage ID for SMP value 0x08.
         */
        SMP_VALUE_0x08((byte) 0x08);

        private final byte value;

        KDFUsage(final byte value) {
            this.value = value;
        }
    }

    private OtrCryptoEngine4() {
        // No need to instantiate utility class.
    }

    /**
     * Produce fingerprint for public key.
     *
     * @param publicKey The public key to fingerprint.
     * @return Returns the fingerprint derived from the provided public key.
     */
    public static byte[] fingerprint(@Nonnull final Point publicKey) {
        final byte[] dst = new byte[FINGERPRINT_LENGTH_BYTES];
        kdf1(dst, 0, FINGERPRINT, publicKey.encode(), FINGERPRINT_LENGTH_BYTES);
        return dst;
    }

    /**
     * KDF_1 key derivation function. ({@link #kdf1(byte[], int, KDFUsage, byte[], int)} for more details.)
     *
     * @param usageID    The usage ID to be mixed in the input to KDF1.
     * @param input      Input data.
     * @param outputSize Expected output size.
     * @return Returns byte-array with KDF_1 result.
     */
    public static byte[] kdf1(@Nonnull final KDFUsage usageID, @Nonnull final byte[] input, final int outputSize) {
        requireAtLeast(0, outputSize);
        final byte[] result = new byte[outputSize];
        kdf1(result, 0, usageID, input, outputSize);
        return result;
    }

    /**
     * KDF_1 key derivation function.
     * <p>
     * "KDF_1(usageID || values, output_size) = SHAKE-256("OTRv4" || usageID || values, size)"
     *
     * @param dst        The destination byte array, with 32 bytes available for KDF_1 result.
     * @param offset     The offset position to start writing to the destination byte array.
     * @param usageID    The usage ID to be mixed in with the input to KDF1.
     * @param input      The input data to KDF_1.
     * @param outputSize The size of the derivative output.
     */
    public static void kdf1(@Nonnull final byte[] dst, final int offset, @Nonnull final KDFUsage usageID,
            @Nonnull final byte[] input, final int outputSize) {
        requireNonNull(dst);
        requireAtLeast(0, outputSize);
        assert !allZeroBytes(input) : "Expected non-zero bytes for input. This may indicate that a critical bug is present, or it may be a false warning.";
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(usageID.value);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, outputSize);
    }

    /**
     * SHAKE-256 hash function.
     *
     * @param dst        The destination for the hash digest.
     * @param offset     The offset on which to start writing the digest.
     * @param input      The input data for the hash function.
     * @param outputSize The output size of the digest.
     */
    static void shake256(@Nonnull final byte[] dst, final int offset, @Nonnull final byte[] input, final int outputSize) {
        requireNonNull(dst);
        requireAtLeast(0, outputSize);
        assert !allZeroBytes(input) : "Expected non-zero bytes for input. This may indicate that a critical bug is present, or it may be a false warning.";
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, outputSize);
    }

    /**
     * HashToScalar.
     * <p>
     * As defined in section "HashToScalar" in OTRv4 specification.
     *
     * @param usageID The usage ID to be mixed in with the input to KDF1.
     * @param d       array of bytes
     * @return Returns derived scalar value.
     */
    @Nonnull
    public static BigInteger hashToScalar(@Nonnull final KDFUsage usageID, @Nonnull final byte[] d) {
        assert !allZeroBytes(d) : "Expected non-zero bytes for input. This may indicate that a critical bug is present, or it may be a false warning.";
        // "Compute h = KDF_1(d, 64) as an unsigned value, little-endian."
        final byte[] hashedD = kdf1(usageID, d, HASH_TO_SCALAR_LENGTH_BYTES);
        final BigInteger h = decodeLittleEndian(hashedD);
        clear(hashedD);
        // "Return h (mod q)"
        return h.mod(primeOrder());
    }

    /**
     * Verify Point instance as EdDSA public key.
     *
     * @param point EdDSA public key, represented as Point.
     * @throws OtrCryptoException Thrown in case point is illegal, i.e. does not lie on the Ed448-Goldilocks curve.
     */
    public static void verifyEdDSAPublicKey(@Nonnull final Point point) throws OtrCryptoException {
        // FIXME should we do more input verification here? Somehow it seems unlikely that identity is considered a EdDSA key pair.
        if (!Ed448.contains(point)) {
            throw new OtrCryptoException("Illegal public key.");
        }
    }

    /**
     * Decode an EdDSA public key from RFC 8032 byte-encoding.
     *
     * @param pointBytes The bytes representing point.
     * @return Returns Point instance.
     * @throws OtrCryptoException Throws in case of bytes contain invalid data.
     */
    @Nonnull
    public static Point decodePoint(@Nonnull final byte[] pointBytes) throws OtrCryptoException {
        try {
            return Points.decode(pointBytes);
        } catch (final InvalidDataException ex) {
            throw new OtrCryptoException("Invalid Ed448 point data.", ex);
        }
    }

    /**
     * Generate a random IV for use in XSalsa20 encryption.
     *
     * @param random a SecureRandom instance
     * @return Returns random nonce for use in XSalsa20 encryption.
     */
    @Nonnull
    public static byte[] generateNonce(@Nonnull final SecureRandom random) {
        final byte[] nonce = new byte[XSALSA20_IV_LENGTH_BYTES];
        random.nextBytes(nonce);
        return nonce;
    }

    /**
     * Encrypt a message using XSalsa20, given the specified IV and key.
     *
     * @param key     the secret key used for encryption (32 bytes)
     * @param iv      the initialization vector (nonce, 24 bytes)
     * @param message the plaintext message to be encrypted (non-null)
     * @return Returns the encrypted content.
     */
    @Nonnull
    public static byte[] encrypt(@Nonnull final byte[] key, @Nonnull final byte[] iv, @Nonnull final byte[] message) {
        assert !allZeroBytes(key) : "Expected non-zero byte array for a key. Something critical might be going wrong.";
        assert !allZeroBytes(iv) : "Expected non-zero byte array for a iv. Something critical might be going wrong.";
        requireNonNull(message);
        final XSalsa20Engine engine = new XSalsa20Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key, 0, key.length), requireNonNull(iv)));
        final byte[] out = new byte[message.length];
        if (engine.processBytes(message, 0, message.length, out, 0) != message.length) {
            throw new IllegalStateException("Expected to process exactly full size of the message.");
        }
        return out;
    }

    /**
     * Decrypt a ciphertext using XSalsa20, given the specified IV and key.
     *
     * @param key        the secret key used for decryption (32 bytes)
     * @param iv         the initialization vector (nonce, 24 bytes)
     * @param ciphertext te ciphertext to be decrypted (non-null)
     * @return Returns the decrypted (plaintext) content.
     */
    @Nonnull
    public static byte[] decrypt(@Nonnull final byte[] key, @Nonnull final byte[] iv, @Nonnull final byte[] ciphertext) {
        assert !allZeroBytes(key) : "Expected non-zero byte array for a key. Something critical might be going wrong.";
        assert !allZeroBytes(iv) : "Expected non-zero byte array for a iv. Something critical might be going wrong.";
        requireNonNull(ciphertext);
        final XSalsa20Engine engine = new XSalsa20Engine();
        engine.init(false, new ParametersWithIV(new KeyParameter(key, 0, key.length),
                requireNonNull(iv)));
        final byte[] out = new byte[ciphertext.length];
        if (engine.processBytes(ciphertext, 0, ciphertext.length, out, 0) != ciphertext.length) {
            throw new IllegalStateException("Expected to process exactly full size of the message.");
        }
        return out;
    }

    /**
     * Ring signature generation. (RSig)
     *
     * @param random          A secure random instance.
     * @param longTermKeyPair The long-term Ed448 key pair.
     * @param A1              Public key to be included in the signature.
     * @param A2              Public key to be included in the signature.
     * @param A3              Public key to be included in the signature.
     * @param m               The message for which the signature should be generated.
     * @return Returns the sigma values that represent the ring signature.
     */
    @SuppressWarnings ({"PMD.FormalParameterNamingConventions", "PMD.LocalVariableNamingConventions"})
    @Nonnull
    public static Sigma ringSign(@Nonnull final SecureRandom random, @Nonnull final EdDSAKeyPair longTermKeyPair,
            @Nonnull final Point A1, @Nonnull final Point A2, @Nonnull final Point A3, @Nonnull final byte[] m) {
        if (!Ed448.contains(longTermKeyPair.getPublicKey()) || !Ed448.contains(A1) || !Ed448.contains(A2) || !Ed448.contains(A3)) {
            throw new IllegalArgumentException("Illegal point provided. Points need to be on curve Ed448.");
        }
        if (Points.equals(A1, A2) || Points.equals(A2, A3) || Points.equals(A1, A3)) {
            throw new IllegalArgumentException("Some of the points are equal. It defeats the purpose of the ring signature.");
        }
        final Point longTermPublicKey = longTermKeyPair.getPublicKey();
        // Calculate equality to each of the provided public keys.
        final boolean eq1 = Points.equals(longTermPublicKey, A1);
        final boolean eq2 = Points.equals(longTermPublicKey, A2);
        final boolean eq3 = Points.equals(longTermPublicKey, A3);
        // "Pick random values t1, c2, c3, r2, r3 in q."
        final BigInteger ti = generateRandomValue(random);
        final BigInteger cj = generateRandomValue(random);
        final BigInteger rj = generateRandomValue(random);
        final BigInteger ck = generateRandomValue(random);
        final BigInteger rk = generateRandomValue(random);
        final Point T1;
        final Point T2;
        final Point T3;
        // FIXME replace with constant-time selection
        if (eq1) {
            // "Compute T1 = G * t1."
            T1 = multiplyByBase(ti);
            // "Compute T2 = G * r2 + A2 * c2."
            T2 = multiplyByBase(rj).add(A2.multiply(cj));
            // "Compute T3 = G * r3 + A3 * c3."
            T3 = multiplyByBase(rk).add(A3.multiply(ck));
        } else if (eq2) {
            T1 = multiplyByBase(rj).add(A1.multiply(cj));
            T2 = multiplyByBase(ti);
            T3 = multiplyByBase(rk).add(A3.multiply(ck));
        } else if (eq3) {
            T1 = multiplyByBase(rj).add(A1.multiply(cj));
            T2 = multiplyByBase(rk).add(A2.multiply(ck));
            T3 = multiplyByBase(ti);
        } else {
            throw new IllegalArgumentException("Long-term key pair should match at least one of the public keys.");
        }
        // "Compute c = HashToScalar(0x1D || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)."
        final BigInteger q = primeOrder();
        final BigInteger c;
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            basePoint().encodeTo(buffer);
            encodeLittleEndianTo(buffer, q);
            A1.encodeTo(buffer);
            A2.encodeTo(buffer);
            A3.encodeTo(buffer);
            T1.encodeTo(buffer);
            T2.encodeTo(buffer);
            T3.encodeTo(buffer);
            buffer.write(m, 0, m.length);
            c = hashToScalar(AUTH, buffer.toByteArray());
        } catch (final IOException e) {
            throw new IllegalStateException("Failed to write point to buffer.", e);
        }
        // "Compute c1 = c - c2 - c3 (mod q)."
        final BigInteger ci = c.subtract(cj).subtract(ck).mod(q);
        // "Compute r1 = t1 - c1 * a1 (mod q)."
        final BigInteger ri = ti.subtract(ci.multiply(longTermKeyPair.getSecretKey())).mod(q);
        // FIXME replace with constant-time selection
        if (eq1) {
            // "Send sigma = (c1, r1, c2, r2, c3, r3)."
            return new Sigma(ci, ri, cj, rj, ck, rk);
        } else if (eq2) {
            return new Sigma(cj, rj, ci, ri, ck, rk);
        } else if (eq3) {
            return new Sigma(cj, rj, ck, rk, ci, ri);
        } else {
            throw new IllegalStateException("BUG: eq1 or eq2 or e3 should always be true.");
        }
    }

    /**
     * Generate a new random value in Z_q.
     *
     * @param random SecureRandom instance
     * @return Returns a newly generated random value.
     */
    // FIXME SMP: not sure what this is exactly. Need to see how to reliably generate these values.
    public static BigInteger generateRandomValueInZq(@Nonnull final SecureRandom random) {
        return generateRandomValue(random);
    }

    // FIXME how to reliable generate random value "in q"? (Is this correct for scalars? 0 <= x < q (... or [0,q-1])?
    private static BigInteger generateRandomValue(@Nonnull final SecureRandom random) {
        // FIXME size of 54 bytes was arbitrarily chosen to work within the bounds of q. (Needs to be replaced with verified solution)
        final byte[] data = new byte[54];
        random.nextBytes(data);
        // FIXME generate larger value, then mod q?
        final BigInteger value = decodeLittleEndian(data);
        assert ZERO.compareTo(value) <= 0 && primeOrder().compareTo(value) > 0
            : "Generated scalar value should always be less to be valid, i.e. greater or equal to zero and smaller than prime order.";
        return value;
    }

    /**
     * Ring signature verification. (RVrf)
     *
     * @param A1    Public key 1.
     * @param A2    Public key 2.
     * @param A3    Public key 3.
     * @param sigma The sigma containing the ring signature components.
     * @param m     The message for which the signature was generated.
     * @throws OtrCryptoException In case verification fails on sigma, or in case A1, A2 or A3 contains an illegal
     *                            value.
     */
    @SuppressWarnings ({"PMD.FormalParameterNamingConventions", "PMD.LocalVariableNamingConventions"})
    public static void ringVerify(@Nonnull final Point A1, @Nonnull final Point A2, @Nonnull final Point A3,
            @Nonnull final Sigma sigma, @Nonnull final byte[] m) throws OtrCryptoException {
        if (!Ed448.contains(A1) || !Ed448.contains(A2) || !Ed448.contains(A3)) {
            throw new OtrCryptoException("One of the public keys is invalid.");
        }
        final BigInteger q = primeOrder();
        // "Parse sigma to retrieve components (c1, r1, c2, r2, c3, r3)."
        // Parsing happened outside of this method already. We expect a "sigma" instance to be provided.
        // "Compute T1 = G * r1 + A1 * c1"
        final Point T1 = multiplyByBase(sigma.r1).add(A1.multiply(sigma.c1));
        // "Compute T2 = G * r2 + A2 * c2"
        final Point T2 = multiplyByBase(sigma.r2).add(A2.multiply(sigma.c2));
        // "Compute T3 = G * r3 + A3 * c3"
        final Point T3 = multiplyByBase(sigma.r3).add(A3.multiply(sigma.c3));
        // "Compute c = HashToScalar(0x1D || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)."
        final BigInteger c;
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            basePoint().encodeTo(buffer);
            encodeLittleEndianTo(buffer, q);
            A1.encodeTo(buffer);
            A2.encodeTo(buffer);
            A3.encodeTo(buffer);
            T1.encodeTo(buffer);
            T2.encodeTo(buffer);
            T3.encodeTo(buffer);
            buffer.write(m, 0, m.length);
            c = hashToScalar(AUTH, buffer.toByteArray());
        } catch (final IOException e) {
            throw new IllegalStateException("Failed to write point to buffer.", e);
        }
        // "Check if c ≟ c1 + c2 + c3 (mod q). If it is true, verification succeeds. If not, it fails."
        if (!c.equals(sigma.c1.add(sigma.c2).add(sigma.c3).mod(q))) {
            throw new OtrCryptoException("Ring signature failed verification.");
        }
    }

    /**
     * Data structure that captures all related data for 'sigma' in the Ring Signature.
     */
    public static final class Sigma implements OtrEncodable {
        private final BigInteger c1;
        private final BigInteger r1;
        private final BigInteger c2;
        private final BigInteger r2;
        private final BigInteger c3;
        private final BigInteger r3;

        private Sigma(@Nonnull final BigInteger c1, @Nonnull final BigInteger r1, @Nonnull final BigInteger c2,
                @Nonnull final BigInteger r2, @Nonnull final BigInteger c3, @Nonnull final BigInteger r3) {
            this.c1 = requireNonNull(c1);
            this.r1 = requireNonNull(r1);
            this.c2 = requireNonNull(c2);
            this.r2 = requireNonNull(r2);
            this.c3 = requireNonNull(c3);
            this.r3 = requireNonNull(r3);
        }

        /**
         * Read from OTR input stream and parse raw OTR data to extract sigma.
         *
         * @param in the OTR input stream
         * @return Returns sigma as parsed from the data.
         * @throws ProtocolException In case of failure to read sigma from input.
         */
        public static Sigma readFrom(@Nonnull final OtrInputStream in) throws ProtocolException {
            final BigInteger c1 = in.readScalar();
            final BigInteger r1 = in.readScalar();
            final BigInteger c2 = in.readScalar();
            final BigInteger r2 = in.readScalar();
            final BigInteger c3 = in.readScalar();
            final BigInteger r3 = in.readScalar();
            return new Sigma(c1, r1, c2, r2, c3, r3);
        }

        /**
         * Write sigma to provided OtrOutputStream.
         *
         * @param out The output stream.
         */
        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeScalar(this.c1);
            out.writeScalar(this.r1);
            out.writeScalar(this.c2);
            out.writeScalar(this.r2);
            out.writeScalar(this.c3);
            out.writeScalar(this.r3);
        }
    }
}
