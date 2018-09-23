package net.java.otr4j.io.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.OtrCryptoException;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.io.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.io.messages.MysteriousT4.encode;

/**
 * Utility class for AuthIMessage.
 */
// FIXME write unit tests
public final class AuthIMessages {

    private AuthIMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate an Auth-I message.
     *
     * @param message           the Auth-I message to be validated
     * @param queryTag          the query tag
     * @param ourProfilePayload our client profile (as payload)
     * @param profilePayloadBob other party's client profile (as payload)
     * @param x                 ephemeral ECDH public key 'X'
     * @param y                 ephemeral ECDH public key 'Y'
     * @param a                 ephemeral DH public key 'A'
     * @param b                 ephemeral DH public key 'B'
     * @param senderAccountID   sender account ID
     * @param receiverAccountID receiver account ID
     * @throws OtrCryptoException  In case of failure during ring signature verification.
     * @throws ValidationException In case validation fails.
     */
    // FIXME pass ClientProfile i.s.o. ClientProfilePayload. We only need to validate them once.
    public static void validate(@Nonnull final AuthIMessage message, @Nonnull final String queryTag,
            @Nonnull final ClientProfilePayload ourProfilePayload,
            @Nonnull final ClientProfilePayload profilePayloadBob, @Nonnull final Point x, @Nonnull final Point y,
            @Nonnull final BigInteger a, @Nonnull final BigInteger b, @Nonnull final String senderAccountID,
            @Nonnull final String receiverAccountID)
            throws OtrCryptoException, ValidationException {
        if (message.getType() != AuthIMessage.MESSAGE_AUTH_I) {
            throw new IllegalStateException("AUTH_R message should not have any other type than 0x91.");
        }
        final ClientProfile profileBob = profilePayloadBob.validate();
        if (!message.senderInstanceTag.equals(profileBob.getInstanceTag())) {
            throw new ValidationException("Sender instance tag does not match with owner instance tag in client profile.");
        }
        final ClientProfile ourProfile = ourProfilePayload.validate();
        // We don't do extra verification of points here, as these have been verified upon receiving the Identity
        // message. This was the previous message that was sent. So we can assume points are trustworthy.
        final byte[] t = encode(AUTH_I, ourProfilePayload, profilePayloadBob, x, y, a, b,
                message.senderInstanceTag.getValue(), message.receiverInstanceTag.getValue(), queryTag, senderAccountID,
                receiverAccountID);
        // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, X}, t)."
        ringVerify(profileBob.getLongTermPublicKey(), ourProfile.getLongTermPublicKey(), x, message.getSigma(), t);
    }
}
