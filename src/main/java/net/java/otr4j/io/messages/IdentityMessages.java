package net.java.otr4j.io.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.OtrCryptoException;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;

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
     * @param message The identity message.
     * @throws OtrCryptoException  Validation failure of cryptographic components.
     * @throws ValidationException Validation failure of parts of the Identity message.
     */
    // TODO consider wrapping OtrCryptoException in ValidationException.
    public static void validate(@Nonnull final IdentityMessage message) throws OtrCryptoException, ValidationException {
        if (message.getType() != IdentityMessage.MESSAGE_IDENTITY) {
            throw new IllegalStateException("Identity message should not have any other type than 0x08.");
        }
        // TODO consider moving this out to first use case, instead of prematurely validating here.
        final ClientProfile profile = message.getClientProfile().validate();
        if (!message.senderInstanceTag.equals(profile.getInstanceTag())) {
            throw new ValidationException("Sender instance tag does not match with owner instance tag in client profile.");
        }
        verifyECDHPublicKey(message.getY());
        verifyDHPublicKey(message.getB());
    }
}
