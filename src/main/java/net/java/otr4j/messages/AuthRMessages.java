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

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.crypto.ed448.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;

/**
 * Utility class for AuthRMessage. (Auth-R messages)
 */
public final class AuthRMessages {

    private AuthRMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate an AuthRMessage, using additional parameters to provide required data.
     *
     * @param message                    the AUTH_R message
     * @param ourClientProfilePayload    our ClientProfile payload instance (non-validated)
     * @param ourProfile                 our Client Profile instance (the same as the payload, but validated)
     * @param theirProfile               their Client Profile instance
     * @param senderAccountID            the sender's account ID
     * @param receiverAccountID          the Receiver's account ID
     * @param receiverECDHPublicKey      the receiver's ECDH public key
     * @param receiverDHPublicKey        the receiver's DH public key
     * @param receiverFirstECDHPublicKey the receiver's first ECDH public key after DAKE completes
     * @param receiverFirstDHPublicKey   the receiver's first DH public key after DAKE completes
     * @param queryTag                   the query tag
     * @throws ValidationException In case the message fails validation.
     */
    public static void validate(@Nonnull final AuthRMessage message,
            @Nonnull final ClientProfilePayload ourClientProfilePayload, @Nonnull final ClientProfile ourProfile,
            @Nonnull final ClientProfile theirProfile, @Nonnull final String senderAccountID,
            @Nonnull final String receiverAccountID, @Nonnull final Point receiverECDHPublicKey,
            @Nonnull final BigInteger receiverDHPublicKey, @Nonnull final Point receiverFirstECDHPublicKey,
            @Nonnull final BigInteger receiverFirstDHPublicKey, @Nonnull final String queryTag)
            throws ValidationException {
        try {
            verifyECDHPublicKey(message.getX());
            verifyDHPublicKey(message.getA());
            verifyECDHPublicKey(message.getOurFirstECDHPublicKey());
            verifyDHPublicKey(message.getOurFirstDHPublicKey());
        } catch (final net.java.otr4j.crypto.ed448.ValidationException | OtrCryptoException e) {
            throw new ValidationException("Illegal ephemeral public key.", e);
        }
        if (!message.senderInstanceTag.equals(theirProfile.getInstanceTag())) {
            throw new ValidationException("Sender instance tag does not match with owner instance tag in client profile.");
        }
        final byte[] t = encode(AUTH_R, message.getClientProfile(), ourClientProfilePayload, message.getX(),
                receiverECDHPublicKey, message.getA(), receiverDHPublicKey, message.getOurFirstECDHPublicKey(),
                message.getOurFirstDHPublicKey(), receiverFirstECDHPublicKey, receiverFirstDHPublicKey,
                message.senderInstanceTag, message.receiverInstanceTag, queryTag, senderAccountID, receiverAccountID);
        try {
            ringVerify(ourProfile.getForgingKey(), theirProfile.getLongTermPublicKey(), receiverECDHPublicKey,
                    message.getSigma(), t);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Ring signature failed verification.", e);
        }
    }
}
