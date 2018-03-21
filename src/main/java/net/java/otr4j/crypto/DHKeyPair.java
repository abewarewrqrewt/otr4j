package net.java.otr4j.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import static net.java.otr4j.crypto.OtrCryptoEngine.GENERATOR;

public final class DHKeyPair {

    private static final String KF_DH = "DH";

    private static final BigInteger MODULUS = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);

    private static final BigInteger G3 = BigInteger.valueOf(2L);

    private static final int DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH = 3072;

    private DHKeyPair(final byte[] r) {
        // FIXME implement
    }

    @Nonnull
    public static KeyPair generate(@Nonnull final SecureRandom secureRandom) {

        // Generate a AsymmetricCipherKeyPair using BC.
        final DHParameters dhParams = new DHParameters(MODULUS, G3, null, DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH);
        final DHKeyGenerationParameters params = new DHKeyGenerationParameters(secureRandom, dhParams);
        final DHKeyPairGenerator kpGen = new DHKeyPairGenerator();

        kpGen.init(params);
        final AsymmetricCipherKeyPair pair = kpGen.generateKeyPair();
        final DHPublicKeyParameters pub = convertToPublicKeyParams(pair.getPublic());
        final DHPrivateKeyParameters priv = convertToPrivateKeyParams(pair.getPrivate());

        final KeyFactory keyFac;
        try {
            keyFac = KeyFactory.getInstance(KF_DH);
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("DH key factory unavailable.", ex);
        }

        final DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(pub.getY(), MODULUS, GENERATOR);
        final DHPublicKey pubKey;
        try {
            pubKey = (DHPublicKey) keyFac.generatePublic(pubKeySpecs);
        } catch (final InvalidKeySpecException ex) {
            throw new IllegalStateException("Failed to generate DH public key.", ex);
        }

        final DHParameters dhParameters = priv.getParameters();
        final DHPrivateKeySpec privKeySpecs = new DHPrivateKeySpec(priv.getX(),dhParameters.getP(), dhParameters.getG());
        final DHPrivateKey privKey;
        try {
            privKey = (DHPrivateKey) keyFac.generatePrivate(privKeySpecs);
        } catch (final InvalidKeySpecException ex) {
            throw new IllegalStateException("Failed to generate DH private key.", ex);
        }

        return new KeyPair(pubKey, privKey);
    }

    @Nonnull
    private static DHPublicKeyParameters convertToPublicKeyParams(@Nonnull final AsymmetricKeyParameter params) {
        if (!(params instanceof DHPublicKeyParameters)) {
            throw new IllegalArgumentException("Expected to acquire DHPublicKeyParameters instance, but it isn't. (" + params.getClass().getCanonicalName() + ")");
        }
        return (DHPublicKeyParameters) params;
    }

    @Nonnull
    private static DHPrivateKeyParameters convertToPrivateKeyParams(@Nonnull final AsymmetricKeyParameter params) {
        if (!(params instanceof DHPrivateKeyParameters)) {
            throw new IllegalArgumentException("Expected to acquire DHPrivateKeyParameters instance, but it isn't. (" + params.getClass().getCanonicalName() + ")");
        }
        return (DHPrivateKeyParameters) params;
    }
}
