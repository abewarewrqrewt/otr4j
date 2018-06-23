package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;

public final class IdentityMessages {

    private IdentityMessages() {
        // No need to instantiate utility class.
    }

    public static void validate(@Nonnull final IdentityMessage message) throws OtrCryptoException, ClientProfilePayload.ValidationException {

        if (message.getType() != IdentityMessage.MESSAGE_IDENTITY) {
            throw new IllegalStateException("Identity message should not have any other type than 0x08.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        // FIXME consider moving this out to first use case, instead of prematurely validating here.
        message.getClientProfile().validate();
        verifyECDHPublicKey(message.getY());
        verifyDHPublicKey(message.getB());
        // FIXME finish implementation.
        throw new UnsupportedOperationException("To be implemented.");
    }
}
