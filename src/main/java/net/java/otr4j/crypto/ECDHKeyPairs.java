package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;

/**
 * Utility class for ECDH key pair instances.
 */
public final class ECDHKeyPairs {

    private ECDHKeyPairs() {
        // No need to instantiate utility class.
    }

    /**
     * Verify a ECDH public key.
     *
     * @param point The ECDH public key.
     */
    public static void verifyECDHPublicKey(@Nonnull final Point point) throws OtrCryptoException {
        if (!Ed448.contains(point)) {
            throw new OtrCryptoException("ECDH public key is not on curve Ed448-Goldilocks.");
        }
    }
}
