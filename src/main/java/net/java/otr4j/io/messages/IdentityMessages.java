package net.java.otr4j.io.messages;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.profile.UserProfiles;
import nl.dannyvanheumen.joldilocks.Ed448;

import javax.annotation.Nonnull;

public final class IdentityMessages {

    private IdentityMessages() {
        // No need to instantiate utility class.
    }

    public static void verify(@Nonnull final IdentityMessage message) throws OtrException {
        if (message.getType() != IdentityMessage.MESSAGE_IDENTITY) {
            throw new IllegalStateException("Identity message should not have any other type than 0x08.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        UserProfiles.validate(message.getUserProfile());
        if (!Ed448.contains(message.getY())) {
            throw new OtrException("OTR requires valid Point Y.");
        }
        DHKeyPair.verifyPublicKey(message.getB());
    }
}
