package net.java.otr4j.crypto;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import static java.util.Objects.requireNonNull;

/**
 * Key pair for DH private and public key.
 */
public final class DHKeyPairJ {

    private final DHPrivateKey privateKey;
    private final DHPublicKey publicKey;

    /**
     * Constructor to create key pair of private and corresponding public key.
     *
     * @param privateKey the private key
     * @param publicKey  the corresponding public key
     */
    public DHKeyPairJ(@Nonnull final DHPrivateKey privateKey, @Nonnull final DHPublicKey publicKey) {
        this.privateKey = requireNonNull(privateKey);
        this.publicKey = requireNonNull(publicKey);
    }

    /**
     * Get private key from the key pair.
     *
     * @return the private key
     */
    @Nonnull
    public DHPrivateKey getPrivate() {
        return privateKey;
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
}
