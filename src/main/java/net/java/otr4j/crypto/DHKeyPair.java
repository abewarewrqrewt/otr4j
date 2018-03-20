package net.java.otr4j.crypto;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.security.SecureRandom;

// TODO Is it okay that we perform DH value handling ourselves instead of going through the obscure JCA key factories and agreements?
public final class DHKeyPair {

    private static final BigInteger MODULUS = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);

    private static final BigInteger G3 = BigInteger.valueOf(2L);

    private static final int DH_PRIVATE_KEY_LENGTH_BYTES = 80;

    private final BigInteger sk;

    private final BigInteger pk;

    private DHKeyPair(@Nonnull final byte[] r) {
        this.sk = new BigInteger(1, r);
        this.pk = G3.modPow(this.sk, MODULUS);
    }

    /**
     * Generate a new DH key pair.
     *
     * @param random An instance of secure random.
     * @return Returns generated DH key pair.
     */
    @Nonnull
    public static DHKeyPair generate(@Nonnull final SecureRandom random) {
        final byte[] r = new byte[DH_PRIVATE_KEY_LENGTH_BYTES];
        random.nextBytes(r);
        return new DHKeyPair(r);
    }

    /**
     * Get the public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public BigInteger getPk() {
        return this.pk;
    }

    /**
     * Generate the shared secret of this DH key pair combined with the provided public key.
     *
     * @param otherPublicKey The other's public key to use in shared secret generation.
     * @return Returns the generated shared secret.
     */
    @Nonnull
    public BigInteger generateSharedSecret(@Nonnull final BigInteger otherPublicKey) {
        return otherPublicKey.modPow(this.sk, MODULUS);
    }

    /**
     * Verify Diffie-Hellman public key. (3072 bit keys as defined in OTRv4.)
     */
    @Nonnull
    public static void verify(@Nonnull final DHPublicKey pk) {
        // FIXME implement 3072 DH verification
        throw new UnsupportedOperationException("To be implemented.");
    }
}
