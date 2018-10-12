package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;
import nl.dannyvanheumen.joldilocks.Points;

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
     * @throws ValidationException In case of illegal point value.
     */
    public static void verifyECDHPublicKey(@Nonnull final Point point) throws ValidationException {
        // TODO is there anything more to testing correct ECDH public key? (Check for identity?)
        if (Points.checkIdentity(point)) {
            // FIXME identity-check may be redundant as will already be performed in 'Ed448.contains'.
            throw new ValidationException("Public key cannot be identity.");
        }
        if (!Ed448.contains(point)) {
            throw new ValidationException("Public key is not on curve Ed448-Goldilocks.");
        }
    }
}
