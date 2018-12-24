/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.messages.MysteriousT4.encode;

/**
 * Utility class for AuthIMessage.
 */
public final class AuthIMessages {

    private AuthIMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate an Auth-I message.
     *
     * @param message           the Auth-I message to be validated
     * @param queryTag          the query tag
     * @param ourProfilePayload our client profile (non-validated, as payload)
     * @param ourProfile        our client profile
     * @param profileBobPayload other party's client profile (as payload)
     * @param profileBob        other party's client profile, validated
     * @param x                 ephemeral ECDH public key 'X'
     * @param y                 ephemeral ECDH public key 'Y'
     * @param a                 ephemeral DH public key 'A'
     * @param b                 ephemeral DH public key 'B'
     * @param senderAccountID   sender account ID
     * @param receiverAccountID receiver account ID
     * @throws ValidationException In case validation fails.
     */
    public static void validate(@Nonnull final AuthIMessage message, @Nonnull final String queryTag,
            @Nonnull final ClientProfilePayload ourProfilePayload, @Nonnull final ClientProfile ourProfile,
            @Nonnull final ClientProfilePayload profileBobPayload, @Nonnull final ClientProfile profileBob,
            @Nonnull final Point x, @Nonnull final Point y, @Nonnull final BigInteger a, @Nonnull final BigInteger b,
            @Nonnull final Point senderFirstECDHPublicKey, @Nonnull final BigInteger senderFirstDHPublicKey,
            @Nonnull final Point receiverFirstECDHPublicKey, @Nonnull final BigInteger receiverFirstDHPublicKey,
            @Nonnull final String senderAccountID, @Nonnull final String receiverAccountID) throws ValidationException {
        if (!message.senderInstanceTag.equals(profileBob.getInstanceTag())) {
            throw new ValidationException("Sender instance tag does not match with owner instance tag in client profile.");
        }
        // We don't do extra verification of points here, as these have been verified upon receiving the Identity
        // message. This was the previous message that was sent. So we can assume points are trustworthy.
        final byte[] t = encode(AUTH_I, ourProfilePayload, profileBobPayload, x, y, a, b,
                senderFirstECDHPublicKey, senderFirstDHPublicKey, receiverFirstECDHPublicKey, receiverFirstDHPublicKey,
                message.senderInstanceTag.getValue(), message.receiverInstanceTag.getValue(), queryTag, senderAccountID,
                receiverAccountID);
        try {
            ringVerify(profileBob.getLongTermPublicKey(), ourProfile.getForgingKey(), x, message.getSigma(), t);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Ring signature verification failed.", e);
        }
    }
}
