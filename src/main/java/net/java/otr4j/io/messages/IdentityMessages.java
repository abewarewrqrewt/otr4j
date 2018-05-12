package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.UserProfiles;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.DHKeyPairs.verifyPublicKey;
import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.profile.UserProfiles.validate;

public final class IdentityMessages {

    private IdentityMessages() {
        // No need to instantiate utility class.
    }

    public static void verify(@Nonnull final IdentityMessage message) throws UserProfiles.InvalidUserProfileException,
        OtrCryptoException {

        if (message.getType() != IdentityMessage.MESSAGE_IDENTITY) {
            throw new IllegalStateException("Identity message should not have any other type than 0x08.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        validate(message.getUserProfile());
        verifyECDHPublicKey(message.getY());
        verifyPublicKey(message.getB());
    }
}
