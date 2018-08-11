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
     * @throws OtrCryptoException In case of illegal point value.
     */
    public static void verifyECDHPublicKey(@Nonnull final Point point) throws OtrCryptoException {
        // FIXME is there anything more to testing correct ECDH public key? (Check for identity?)
        if (!Ed448.contains(point)) {
            throw new OtrCryptoException("ECDH public key is not on curve Ed448-Goldilocks.");
        }
    }
}
