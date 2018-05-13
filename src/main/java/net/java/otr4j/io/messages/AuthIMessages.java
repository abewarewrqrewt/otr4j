package net.java.otr4j.io.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.UserProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;

/**
 * Utility class for AuthIMessage.
 */
// FIXME write unit tests
public final class AuthIMessages {

    private AuthIMessages() {
        // No need to instantiate utility class.
    }

    public static void validate(@Nonnull final AuthIMessage message, @Nonnull final String queryTag,
                                @Nonnull final UserProfile ourProfile, @Nonnull final UserProfile profileBob,
                                @Nonnull final Point x, @Nonnull final Point y, @Nonnull final BigInteger a,
                                @Nonnull final BigInteger b, @Nonnull final InstanceTag senderTag,
                                @Nonnull final InstanceTag receiverTag, @Nonnull final String senderAccountID,
                                @Nonnull final String receiverAccountID) throws OtrCryptoException {
        if (message.getType() != AuthIMessage.MESSAGE_AUTH_I) {
            throw new IllegalStateException("AUTH_R message should not have any other type than 0x91.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        final byte[] t = MysteriousT4.encode(ourProfile, profileBob, x, y, a, b, senderTag, receiverTag, queryTag,
            senderAccountID, receiverAccountID);
        // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, Y}, t)."
        ringVerify(profileBob.getLongTermPublicKey(), ourProfile.getLongTermPublicKey(), x, message.getSigma(), t);
    }
}
