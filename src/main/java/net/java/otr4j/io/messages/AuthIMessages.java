package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.ClientProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.io.messages.MysteriousT4.encode;

/**
 * Utility class for AuthIMessage.
 */
// FIXME write unit tests
public final class AuthIMessages {

    private AuthIMessages() {
        // No need to instantiate utility class.
    }

    // TODO ensure that sender and receiver instance tags are verified prior to arriving here!
    // FIXME pass ClientProfile i.s.o. ClientProfilePayload. We only need to validate them once.
    public static void validate(@Nonnull final AuthIMessage message, @Nonnull final String queryTag,
                                @Nonnull final ClientProfilePayload ourProfilePayload,
                                @Nonnull final ClientProfilePayload profilePayloadBob, @Nonnull final Point x,
                                @Nonnull final Point y, @Nonnull final BigInteger a, @Nonnull final BigInteger b,
                                @Nonnull final String senderAccountID, @Nonnull final String receiverAccountID)
        throws OtrCryptoException, ValidationException {

        if (message.getType() != AuthIMessage.MESSAGE_AUTH_I) {
            throw new IllegalStateException("AUTH_R message should not have any other type than 0x91.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        final ClientProfile profileBob = profilePayloadBob.validate();
        final ClientProfile ourProfile = ourProfilePayload.validate();
        // We don't do extra verification of points here, as these have been verified upon receiving the Identity
        // message. This was the previous message that was sent. So we can assume points are trustworthy.
        final byte[] t = encode(ourProfilePayload, profilePayloadBob, x, y, a, b, message.senderInstanceTag,
            message.receiverInstanceTag, queryTag, senderAccountID, receiverAccountID);
        // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, X}, t)."
        ringVerify(profileBob.getLongTermPublicKey(), ourProfile.getLongTermPublicKey(), x, message.getSigma(), t);
    }
}
