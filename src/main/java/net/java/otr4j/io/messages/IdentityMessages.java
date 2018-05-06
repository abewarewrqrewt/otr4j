package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.UserProfiles;
import nl.dannyvanheumen.joldilocks.Ed448;

import javax.annotation.Nonnull;
import java.net.ProtocolException;

public final class IdentityMessages {

    private IdentityMessages() {
        // No need to instantiate utility class.
    }

    public static void verify(@Nonnull final IdentityMessage message) throws ProtocolException,
        UserProfiles.InvalidUserProfileException, OtrCryptoException {

        if (message.getType() != IdentityMessage.MESSAGE_IDENTITY) {
            throw new IllegalStateException("Identity message should not have any other type than 0x08.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        UserProfiles.validate(message.getUserProfile());
        if (!Ed448.contains(message.getY())) {
            throw new ProtocolException("OTR requires valid Point Y.");
        }
        DHKeyPair.verifyPublicKey(message.getB());
    }
}
