package net.java.otr4j.crypto;

import javax.annotation.Nonnull;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;

/**
 * Key pair to keep DSA private and corresponding public key.
 */
// TODO consider checking if public key corresponds to private key
public final class DSAKeyPair {

    private final DSAPrivateKey privateKey;
    private final DSAPublicKey publicKey;

    /**
     * Constructor for creating pair of private and public key.
     *
     * @param privateKey the private key
     * @param publicKey  the corresponding public key
     */
    public DSAKeyPair(@Nonnull final DSAPrivateKey privateKey, @Nonnull final DSAPublicKey publicKey) {
        this.privateKey = requireNonNull(privateKey);
        this.publicKey = requireNonNull(publicKey);
    }

    /**
     * Get private key from the key pair.
     *
     * @return the private key
     */
    @Nonnull
    public DSAPrivateKey getPrivate() {
        return privateKey;
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
}
