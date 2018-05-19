package net.java.otr4j.crypto;

import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.KeyPair;
import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ZERO;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;
import static nl.dannyvanheumen.joldilocks.Scalars.encodeLittleEndian;
import static nl.dannyvanheumen.joldilocks.Scalars.encodeLittleEndianTo;

/**
 * Crypto engine for OTRv4.
 */
public final class OtrCryptoEngine4 {

    /**
     * Bit-size for SHAKE-256.
     */
    private static final int SHAKE_256_LENGTH_BITS = 256;

    /**
     * Length of a fingerprint in bytes.
     */
    static final int FINGERPRINT_LENGTH_BYTES = 56;

    /**
     * Length of HashToScalar array of bytes.
     */
    private static final int HASH_TO_SCALAR_LENGTH_BYTES = 64;

    /**
     * Length of the random input data for generating a EdDSA key pair in bytes.
     */
    private static final int EDDSA_KEY_PAIR_RANDOM_INPUT_LENGTH_BYTES = 57;

    /**
     * Prefix used in key derivation functions.
     */
    private static final byte[] OTR4_PREFIX = new byte[]{'O', 'T', 'R', '4'};

    /**
     * Usage ID used for generating ring signatures.
     */
    private static final int USAGE_ID_RING_SIGNATURE = 0x29;

    private OtrCryptoEngine4() {
        // No need to instantiate utility class.
    }

    /**
     * Produce fingerprint for public key.
     *
     * @param dst       The destination byte array to which to write the fingerprint.
     * @param publicKey The public key to fingerprint.
     */
    public static void fingerprint(@Nonnull final byte[] dst, @Nonnull final Point publicKey) {
        requireNonNull(dst);
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        final byte[] encodedPublicKey = publicKey.encode();
        digest.update(encodedPublicKey, 0, encodedPublicKey.length);
        if (digest.doFinal(dst, 0, FINGERPRINT_LENGTH_BYTES) != FINGERPRINT_LENGTH_BYTES) {
            throw new IllegalStateException("Expected exactly " + FINGERPRINT_LENGTH_BYTES + " bytes to be produced for the fingerprint.");
        }
    }

    /**
     * KDF_1 key derivation function. ({@link #kdf1(byte[], int, byte[], int)} for more details.)
     *
     * @param input      Input data.
     * @param outputSize Expected output size.
     * @return Returns byte-array with KDF_1 result.
     */
    // TODO Consider moving all USAGE_ID_... constants to OtrCryptoEngine4 class, instead of having them distributed over all classes that use `kdf1`.
    public static byte[] kdf1(@Nonnull final byte[] input, final int outputSize) {
        requireAtLeast(0, outputSize);
        final byte[] result = new byte[outputSize];
        kdf1(result, 0, input, outputSize);
        return result;
    }

    /**
     * KDF_1 key derivation function.
     * <p>
     * "KDF_1(usageID || values, output_size) = SHAKE-256("OTRv4" || usageID || values, size)"
     *
     * @param outputSize The size of the derivative output.
     * @param dst        The destination byte array, with 32 bytes available for KDF_1 result.
     * @param offset     The offset position to start writing to the destination byte array.
     * @param input      The input data to KDF_1.
     */
    public static void kdf1(@Nonnull final byte[] dst, final int offset, @Nonnull final byte[] input, final int outputSize) {
        requireAtLeast(0, outputSize);
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, outputSize);
    }

    /**
     * HashToScalar.
     *
     * As defined in section "HashToScalar" in OTRv4 specification.
     *
     * @param d array of bytes
     * @return Returns derived scalar value.
     */
    @Nonnull
    public static BigInteger hashToScalar(@Nonnull final byte[] d) {
        // "Compute h = KDF_1(d, 64) as an unsigned value, little-endian."
        final byte[] hashedD = kdf1(d, HASH_TO_SCALAR_LENGTH_BYTES);
        final BigInteger h = decodeLittleEndian(hashedD);
        // "Return h (mod q)"
        return h.mod(primeOrder());
    }

    /**
     * Generate a EdDSA (long-term) key pair. The key pair itself will be requested from the Engine host. This method is
     * there for convenience, to be used by Engine host implementations.
     *
     * @param random Source of secure random data.
     * @return Returns the generated key pair.
     */
    @Nonnull
    public static KeyPair generateEdDSAKeyPair(@Nonnull final SecureRandom random) {
        final byte[] data = new byte[EDDSA_KEY_PAIR_RANDOM_INPUT_LENGTH_BYTES];
        random.nextBytes(data);
        return Ed448.generate(data);
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
     * Encrypt a message using XSalsa20, given the specified IV and key.
     *
     * @param key     the secret key used for encryption (32 bytes)
     * @param iv      the initialization vector (nonce, 24 bytes)
     * @param message the plaintext message to be encrypted (non-null)
     * @return Returns the encrypted content.
     */
    @Nonnull
    public static byte[] encrypt(@Nonnull final byte[] key, @Nonnull final byte[] iv, @Nonnull final byte[] message) {
        requireNonNull(message);
        final XSalsa20Engine engine = new XSalsa20Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key, 0, key.length),
            requireNonNull(iv)));
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
     * @param A1              Other public key to be included in the signature.
     * @param A2              Other public key to be included in the signature.
     * @param A3              Other public key to be included in the signature.
     * @param m               The message for which the signature should be generated.
     */
    // FIXME write unit tests for ring signatures
    // TODO look into details on constant time operations for ring signatures. These may be extra requirements to the implementation.
    @Nonnull
    public static Sigma ringSign(@Nonnull final SecureRandom random, @Nonnull final KeyPair longTermKeyPair,
                                 @Nonnull final Point A1, @Nonnull final Point A2, @Nonnull final Point A3,
                                 @Nonnull final byte[] m) {
        if (!Ed448.contains(A1) || !Ed448.contains(A2) || !Ed448.contains(A3)) {
            throw new IllegalArgumentException("Illegal point provided. Valid points need to be on the curve.");
        }
        final BigInteger q = primeOrder();
        // "Pick random values t1, c2, c3, r2, r3 in q."
        final BigInteger t1 = generateRandomValue(random);
        final BigInteger c2 = generateRandomValue(random);
        final BigInteger c3 = generateRandomValue(random);
        final BigInteger r2 = generateRandomValue(random);
        final BigInteger r3 = generateRandomValue(random);
        // "Compute T1 = G * t1."
        final Point T1 = multiplyByBase(t1);
        // "Compute T2 = G * r2 + A2 * c2."
        final Point T2 = multiplyByBase(r2).add(A2.multiply(c2));
        // "Compute T3 = G * r3 + A3 * c3."
        final Point T3 = multiplyByBase(r3).add(A3.multiply(c3));
        // "Compute c = HashToScalar(0x29 || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)."
        final BigInteger c;
        try (final ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            buffer.write(USAGE_ID_RING_SIGNATURE);
            basePoint().encodeTo(buffer);
            encodeLittleEndianTo(buffer, q);
            A1.encodeTo(buffer);
            A2.encodeTo(buffer);
            A3.encodeTo(buffer);
            T1.encodeTo(buffer);
            T2.encodeTo(buffer);
            T3.encodeTo(buffer);
            buffer.write(m);
            c = hashToScalar(buffer.toByteArray());
        } catch (final IOException e) {
            throw new IllegalStateException("Failed to write point to buffer.", e);
        }
        // "Compute c1 = c - c2 - c3 (mod q)."
        final BigInteger c1 = c.subtract(c2).subtract(c3).mod(q);
        // "Compute r1 = t1 - c1 * a1 (mod q)."
        final BigInteger r1 = t1.subtract(c1.multiply(longTermKeyPair.getPrivateKey())).mod(q);
        // "Send sigma = (c1, r1, c2, r2, c3, r3)."
        return new Sigma(c1, r1, c2, r2, c3, r3);
    }

    // FIXME how to reliable generate random value "in q"? (Is this correct for scalars? 0 <= x < q (... or [0,q-1])?
    private static BigInteger generateRandomValue(@Nonnull final SecureRandom random) {
        final byte[] data = new byte[57];
        random.nextBytes(data);
        // FIXME verify if and what kind of pruning is needed to guarantee valid value
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
     */
    // FIXME write unit tests for ring signatures
    public static void ringVerify(@Nonnull final Point A1, @Nonnull final Point A2, @Nonnull final Point A3,
                                  @Nonnull final Sigma sigma, @Nonnull final byte[] m) throws OtrCryptoException {
        if (!Ed448.contains(A1) || !Ed448.contains(A2) || !Ed448.contains(A3)) {
            throw new OtrCryptoException("Some of the public keys are invalid.");
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
        // "Compute c = HashToScalar(0x29 || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)."
        final BigInteger c;
        try (final ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            buffer.write(USAGE_ID_RING_SIGNATURE);
            basePoint().encodeTo(buffer);
            encodeLittleEndianTo(buffer, q);
            A1.encodeTo(buffer);
            A2.encodeTo(buffer);
            A3.encodeTo(buffer);
            T1.encodeTo(buffer);
            T2.encodeTo(buffer);
            T3.encodeTo(buffer);
            buffer.write(m, 0, m.length);
            c = hashToScalar(buffer.toByteArray());
        } catch (final IOException e) {
            throw new IllegalStateException("Failed to write base point to buffer.", e);
        }
        // "Check if c ≟ c1 + c2 + c3 (mod q). If it is true, verification succeeds. If not, it fails."
        if (!c.equals(sigma.c1.add(sigma.c2).add(sigma.c3).mod(q))) {
            throw new OtrCryptoException("Ring signature failed verification.");
        }
    }

    /**
     * Data structure that captures all related data for 'sigma' in the Ring Signature.
     */
    // FIXME write unit tests
    public static final class Sigma {
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
         */
        public static Sigma readFrom(@Nonnull final OtrInputStream in) throws IOException {
            final BigInteger c1 = decodeLittleEndian(in.readData());
            final BigInteger r1 = decodeLittleEndian(in.readData());
            final BigInteger c2 = decodeLittleEndian(in.readData());
            final BigInteger r2 = decodeLittleEndian(in.readData());
            final BigInteger c3 = decodeLittleEndian(in.readData());
            final BigInteger r3 = decodeLittleEndian(in.readData());
            return new Sigma(c1, r1, c2, r2, c3, r3);
        }

        /**
         * Write sigma to provided OtrOutputStream.
         *
         * @param out The output stream.
         * @throws IOException Thrown in case of failure to write to output stream.
         */
        public void writeTo(@Nonnull final OtrOutputStream out) throws IOException {
            out.writeData(encodeLittleEndian(this.c1));
            out.writeData(encodeLittleEndian(this.r1));
            out.writeData(encodeLittleEndian(this.c2));
            out.writeData(encodeLittleEndian(this.r2));
            out.writeData(encodeLittleEndian(this.c3));
            out.writeData(encodeLittleEndian(this.r3));
        }
    }
}
