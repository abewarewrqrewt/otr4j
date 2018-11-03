/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.ed448.Ed448.checkIdentity;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;

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
        if (checkIdentity(point)) {
            throw new ValidationException("Public key cannot be identity.");
        }
        if (!containsPoint(point)) {
            throw new ValidationException("Public key is not on curve Ed448-Goldilocks.");
        }
    }
}
