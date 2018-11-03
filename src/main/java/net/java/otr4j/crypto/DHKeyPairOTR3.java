/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

import javax.annotation.Nonnull;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import static java.util.Objects.requireNonNull;

/**
 * Key pair for DH private and public key.
 */
public final class DHKeyPairOTR3 {

    private static final String KA_DH = "DH";
    private static final String KF_DH = "DH";

    private static final int DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH = 320;

    private static final BigInteger BIGINTEGER_TWO = BigInteger.valueOf(2);

    private static final String MODULUS_TEXT = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

    /**
     * Modulus for DH computations.
     */
    public static final BigInteger MODULUS = new BigInteger(MODULUS_TEXT, 16);

    /**
     * Modulus - 2
     */
    public static final BigInteger MODULUS_MINUS_TWO = MODULUS.subtract(BIGINTEGER_TWO);

    /**
     * The generator used in DH.
     */
    public static final BigInteger GENERATOR = new BigInteger("2", 10);

    static {
        try {
            KeyAgreement.getInstance(KA_DH);
            KeyFactory.getInstance(KF_DH);
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Diffie-Hellman algorithm is not available.", e);
        }
    }

    private final DHPrivateKey privateKey;
    private final DHPublicKey publicKey;

    /**
     * Constructor to create key pair of private and corresponding public key.
     *
     * @param privateKey the private key
     * @param publicKey  the corresponding public key
     */
    private DHKeyPairOTR3(@Nonnull final DHPrivateKey privateKey, @Nonnull final DHPublicKey publicKey) {
        this.privateKey = requireNonNull(privateKey);
        this.publicKey = requireNonNull(publicKey);
    }

    /**
     * Generate a DH key pair.
     *
     * @param random the SecureRandom instance
     * @return Returns the DH key pair.
     */
    @Nonnull
    public static DHKeyPairOTR3 generateDHKeyPair(@Nonnull final SecureRandom random) {

        // Generate a AsymmetricCipherKeyPair using BC.
        final DHParameters dhParams = new DHParameters(MODULUS, GENERATOR, null, DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH);
        final DHKeyGenerationParameters params = new DHKeyGenerationParameters(random, dhParams);
        final DHKeyPairGenerator kpGen = new DHKeyPairGenerator();
        kpGen.init(params);
        final KeyFactory keyFac;
        try {
            keyFac = KeyFactory.getInstance(KF_DH);
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("DH key factory unavailable.", ex);
        }

        final AsymmetricCipherKeyPair pair = kpGen.generateKeyPair();
        final DHPublicKeyParameters pub = convertToPublicKeyParams(pair.getPublic());
        final DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(pub.getY(), MODULUS, GENERATOR);
        final DHPublicKey pubKey;
        try {
            pubKey = (DHPublicKey) keyFac.generatePublic(pubKeySpecs);
        } catch (final InvalidKeySpecException ex) {
            throw new IllegalStateException("Failed to generate DH public key.", ex);
        }

        final DHPrivateKeyParameters priv = convertToPrivateKeyParams(pair.getPrivate());
        final DHParameters dhParameters = priv.getParameters();
        final DHPrivateKeySpec privKeySpecs = new DHPrivateKeySpec(priv.getX(), dhParameters.getP(),
                dhParameters.getG());
        final DHPrivateKey privKey;
        try {
            privKey = (DHPrivateKey) keyFac.generatePrivate(privKeySpecs);
        } catch (final InvalidKeySpecException ex) {
            throw new IllegalStateException("Failed to generate DH private key.", ex);
        }

        return new DHKeyPairOTR3(privKey, pubKey);
    }

    /**
     * Convert DH public key from MPI (Big Integer).
     *
     * @param mpi the MPI value that represents the DH public key
     * @return Returns the DH public key.
     * @throws OtrCryptoException In case of illegal MPI value.
     */
    @Nonnull
    public static DHPublicKey fromBigInteger(@Nonnull final BigInteger mpi) throws OtrCryptoException {
        final DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(mpi, MODULUS, GENERATOR);
        try {
            final KeyFactory keyFac = KeyFactory.getInstance(KF_DH);
            return (DHPublicKey) keyFac.generatePublic(pubKeySpecs);
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Failed to instantiate D-H key factory.", ex);
        } catch (final InvalidKeySpecException ex) {
            throw new OtrCryptoException("Invalid D-H public key spec.", ex);
        }
    }

    /**
     * Generate shared secret based on DH key exchange data.
     *
     * @param publicKey  the DH public key (of the other DH key pair)
     * @return Returns the generated shared secret.
     * @throws OtrCryptoException In case of illegal key.
     */
    @Nonnull
    public SharedSecret generateSharedSecret(@Nonnull final DHPublicKey publicKey) throws OtrCryptoException {
        verifyDHPublicKey(publicKey);
        try {
            final KeyAgreement ka = KeyAgreement.getInstance(KA_DH);
            ka.init(this.privateKey);
            ka.doPhase(publicKey, true);
            return new SharedSecret(ka.generateSecret());
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("DH key factory not supported.", ex);
        } catch (final InvalidKeyException ex) {
            throw new OtrCryptoException("Failed to generate shared secret.", ex);
        }
    }

    /**
     * Get public key from the key pair.
     *
     * @return the public key
     */
    @Nonnull
    public DHPublicKey getPublic() {
        return publicKey;
    }

    /**
     * Verify that provided DH public key is a valid key.
     *
     * @param dhPublicKey DH public key
     * @return Returns DH public key instance if DH public key is valid.
     * @throws OtrCryptoException Throws exception in case of illegal D-H key
     * value.
     */
    @Nonnull
    public static DHPublicKey verifyDHPublicKey(@Nonnull final DHPublicKey dhPublicKey) throws OtrCryptoException {
        // Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
        if (dhPublicKey.getY().compareTo(MODULUS_MINUS_TWO) > 0) {
            throw new OtrCryptoException("Illegal D-H Public Key value.");
        }
        if (dhPublicKey.getY().compareTo(BIGINTEGER_TWO) < 0) {
            throw new OtrCryptoException("Illegal D-H Public Key value.");
        }
        return dhPublicKey;
    }

    @Nonnull
    private static DHPublicKeyParameters convertToPublicKeyParams(@Nonnull final AsymmetricKeyParameter params) {
        if (!(params instanceof DHPublicKeyParameters)) {
            throw new IllegalArgumentException("Expected to acquire DHPublicKeyParameters instance, but it isn't. ("
                    + params.getClass().getCanonicalName() + ")");
        }
        return (DHPublicKeyParameters) params;
    }

    @Nonnull
    private static DHPrivateKeyParameters convertToPrivateKeyParams(@Nonnull final AsymmetricKeyParameter params) {
        if (!(params instanceof DHPrivateKeyParameters)) {
            throw new IllegalArgumentException("Expected to acquire DHPrivateKeyParameters instance, but it isn't. ("
                    + params.getClass().getCanonicalName() + ")");
        }
        return (DHPrivateKeyParameters) params;
    }
}
