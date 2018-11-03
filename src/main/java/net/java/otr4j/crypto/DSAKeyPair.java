/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * Key pair to keep DSA private and corresponding public key.
 */
// TODO check how we should restore the DSAKeyPair from the OtrEngineHost perspective. It needs to store and restore the DSAKeyPair on every execution session.
public final class DSAKeyPair {

    private static final String ALGORITHM_DSA = "DSA";

    static {
        try {
            KeyPairGenerator.getInstance(ALGORITHM_DSA);
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("DSA algorithm is not available.", e);
        }
    }

    private final DSAPrivateKey privateKey;
    private final DSAPublicKey publicKey;

    /**
     * Constructor for creating pair of private and public key.
     *
     * @param privateKey the private key
     * @param publicKey  the corresponding public key
     */
    private DSAKeyPair(@Nonnull final DSAPrivateKey privateKey, @Nonnull final DSAPublicKey publicKey) {
        this.privateKey = requireNonNull(privateKey);
        this.publicKey = requireNonNull(publicKey);
    }

    /**
     * Generate a DSA key pair.
     *
     * @return Returns the DSA key pair.
     */
    @Nonnull
    public static DSAKeyPair generateDSAKeyPair() {
        try {
            final KeyPairGenerator kg = KeyPairGenerator.getInstance(ALGORITHM_DSA);
            final java.security.KeyPair keypair = kg.genKeyPair();
            return new DSAKeyPair((DSAPrivateKey) keypair.getPrivate(), (DSAPublicKey) keypair.getPublic());
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Failed to generate DSA key pair: DSA algorithm is unavailable.", e);
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
            @Nonnull final BigInteger q, @Nonnull final BigInteger g) throws OtrCryptoException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_DSA);
            final DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
            return (DSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Failed to initialize DSA key factory: DSA algorithm is not supported.", e);
        } catch (final InvalidKeySpecException e) {
            throw new OtrCryptoException("Read invalid public key from input stream.", e);
        }
    }

    /**
     * Get public key from the key pair.
     *
     * @return the public key
     */
    @Nonnull
    public DSAPublicKey getPublic() {
        return publicKey;
    }

    /**
     * Sign bytes with provided private key.
     *
     * @param b          the source content
     * @return Returns signature in bytes.
     */
    @Nonnull
    public byte[] sign(@Nonnull final byte[] b) {
        final BigInteger q = this.privateKey.getParams().getQ();
        final DSASignature signature = signRS(b);

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
     * @return Signature components 'r' and 's'.
     */
    @Nonnull
    public DSASignature signRS(@Nonnull final byte[] b) {
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
     * Verify DSA signature against expectation using provided DSA public key
     * instance..
     *
     * @param b data expected to be signed.
     * @param pubKey Public key. Provided public key must be an instance of
     * DSAPublicKey.
     * @param rs Components R and S.
     * @throws OtrCryptoException Thrown in case of failed verification.
     */
    public static void verifySignature(@Nonnull final byte[] b, @Nonnull final DSAPublicKey pubKey,
            @Nonnull final byte[] rs) throws OtrCryptoException {
        final int qlen = pubKey.getParams().getQ().bitLength() / 8;
        requireLengthExactly(2 * qlen, rs);
        final ByteBuffer buff = ByteBuffer.wrap(rs);
        final byte[] r = new byte[qlen];
        buff.get(r);
        final byte[] s = new byte[qlen];
        buff.get(s);
        verifySignature(b, pubKey, r, s);
    }

    private static void verifySignature(@Nonnull final byte[] b, @Nonnull final DSAPublicKey pubKey,
            @Nonnull final byte[] r, @Nonnull final byte[] s) throws OtrCryptoException {
        assert !allZeroBytes(r) : "Expected non-zero bytes for r. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(s) : "Expected non-zero bytes for s. This may indicate that a critical bug is present, or it may be a false warning.";
        verifySignature(b, pubKey, new BigInteger(1, r), new BigInteger(1, s));
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
    public static void verifySignature(@Nonnull final byte[] b, @Nonnull final DSAPublicKey pubKey,
            @Nonnull final BigInteger r, @Nonnull final BigInteger s) throws OtrCryptoException {
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
}
