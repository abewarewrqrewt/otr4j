package net.java.otr4j.crypto;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

/**
 * Class representing the DH key pair.
 */
// TODO Is it okay that we perform DH value handling ourselves instead of going through the obscure JCA key factories and agreements? (Consider BC) (I'm not happy with this implementation over standard JCA stuff. However, I also currently cannot find a reason to switch. OTRv4 spec makes it look so simple that there's more risk in trying to use the JCA correctly ... Except maybe for mitigating side-channel attacks such as with timing-related requirements.)
public final class DHKeyPair {

    /**
     * The expected length of DH private key.
     */
    static final int DH_PRIVATE_KEY_LENGTH_BYTES = 80;

    /**
     * The DH prime used as modulus.
     */
    private static final BigInteger MODULUS = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);

    /**
     * The DH generator.
     */
    private static final BigInteger G3 = BigInteger.valueOf(2L);

    /**
     * The upper bound to range of potentially valid values, not taking into account the subprime test.
     */
    private static final BigInteger MODULUS_MINUS_GEN = MODULUS.subtract(G3);

    /**
     * The DH subprime as defined in OTRv4.
     */
    private static final BigInteger Q = new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880AB9472D45556216D6998B8682283D19D42A90D5EF8E5D32767DC2822C6DF785457538ABAE83063ED9CB87C2D370F263D5FAD7466D8499EB8F464A702512B0CEE771E9130D697735F897FD036CC504326C3B01399F643532290F958C0BBD90065DF08BABBD30AEB63B84C4605D6CA371047127D03A72D598A1EDADFE707E884725C16890549D69657FFFFFFFFFFFFFFF", 16);

    /**
     * The secret key of the key pair.
     */
    private final BigInteger secretKey;

    /**
     * The corresponding public key of the key pair.
     */
    private final BigInteger publicKey;

    /**
     * Construct a DH key pair from byte array r, assumed as the secret key. The public key is generated from the
     * provided secret data.
     *
     * @param r secret data to be used as secret key.
     */
    private DHKeyPair(@Nonnull final byte[] r) {
        // FIXME should we verify the resulting secret key using the same verification conditions as the public key?
        this.secretKey = new BigInteger(1, requireLengthExactly(DH_PRIVATE_KEY_LENGTH_BYTES, r));
        this.publicKey = G3.modPow(this.secretKey, MODULUS);
        assert checkPublicKey(this.publicKey) : "Expected generated public key to be valid.";
    }

    /**
     * Get the modulus used by DHKeyPair.
     *
     * @return Returns the modulus used by DHKeyPair.
     */
    static BigInteger modulus() {
        return MODULUS;
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
        return generate(r);
    }

    /**
     * Generate a new DH key pair given random data r.
     *
     * @param r The data, expected to be cryptographically secure random data.
     * @return Returns the DH key pair.
     */
    @Nonnull
    public static DHKeyPair generate(@Nonnull final byte[] r) {
        return new DHKeyPair(r);
    }

    /**
     * Get the public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public BigInteger getPublicKey() {
        return this.publicKey;
    }

    /**
     * Generate the shared secret of this DH key pair combined with the provided public key.
     *
     * @param otherPublicKey The other's public key to use in shared secret generation.
     * @return Returns the generated shared secret.
     */
    @Nonnull
    public BigInteger generateSharedSecret(@Nonnull final BigInteger otherPublicKey) {
        return otherPublicKey.modPow(this.secretKey, MODULUS);
    }

    /**
     * Check if public key is legal. (For 3072 bit keys as defined in OTRv4.)
     *
     * @param publicKey The DH public key.
     * @return Returns true iff legal DH public key value, false otherwise.
     */
    @CheckReturnValue
    public static boolean checkPublicKey(@Nonnull final BigInteger publicKey) {
        return publicKey.compareTo(G3) >= 0 && publicKey.compareTo(MODULUS_MINUS_GEN) <= 0
            && ONE.equals(publicKey.modPow(Q, MODULUS));
    }
}
