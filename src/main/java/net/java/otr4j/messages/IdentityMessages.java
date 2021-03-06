/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.OtrCryptoException;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.ed448.ECDHKeyPairs.verifyECDHPublicKey;

/**
 * Utilities for identity messages.
 */
public final class IdentityMessages {

    private IdentityMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate identity message.
     *
     * @param message      The identity message.
     * @param theirProfile Their profile. The one shipped in the identity message. The message is passed in
     *                     independently such that we can avoid validating the profile multiple times.
     * @throws ValidationException Validation failure of parts of the Identity message.
     */
    // TODO verify that the forced order (validate client profile first) is not an issue according to the spec.
    public static void validate(@Nonnull final IdentityMessage message, @Nonnull final ClientProfile theirProfile)
            throws ValidationException {
        if (!message.senderTag.equals(theirProfile.getInstanceTag())) {
            throw new ValidationException("Sender instance tag does not match with owner instance tag in client profile.");
        }
        try {
            verifyECDHPublicKey(message.y);
            verifyDHPublicKey(message.b);
            verifyECDHPublicKey(message.ourFirstECDHPublicKey);
            verifyDHPublicKey(message.ourFirstDHPublicKey);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException | OtrCryptoException e) {
            throw new ValidationException("Illegal ephemeral public key.", e);
        }
    }
}
