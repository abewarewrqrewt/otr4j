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
     * @param message                 the AUTH_R message
     * @param ourClientProfilePayload our ClientProfile instance
     * @param senderAccountID         the sender's account ID
     * @param receiverAccountID       the Receiver's account ID
     * @param receiverECDHPublicKey   the receiver's ECDH public key
     * @param receiverDHPublicKey     the receiver's DH public key
     * @param queryTag                the query tag
     * @throws OtrCryptoException  In case any cryptographic verification failed, such as ephemeral
     *                             public keys or the ring signature.
     * @throws ValidationException In case any part fails validation.
     */
    public static void validate(@Nonnull final AuthRMessage message, @Nonnull final ClientProfilePayload ourClientProfilePayload,
            @Nonnull final String senderAccountID, @Nonnull final String receiverAccountID,
            @Nonnull final Point receiverECDHPublicKey, @Nonnull final BigInteger receiverDHPublicKey,
            @Nonnull final String queryTag) throws OtrCryptoException, ValidationException {
        try {
            verifyECDHPublicKey(message.getX());
        } catch (final net.java.otr4j.crypto.ed448.ValidationException e) {
            throw new ValidationException("Illegal ECDH public key.", e);
        }
        verifyDHPublicKey(message.getA());
        final ClientProfile theirProfile = message.getClientProfile().validate();
        if (!message.senderInstanceTag.equals(theirProfile.getInstanceTag())) {
            throw new ValidationException("Sender instance tag does not match with owner instance tag in client profile.");
        }
        final ClientProfile ourClientProfile = ourClientProfilePayload.validate();
        // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, Y}, t)."
        final byte[] t = encode(AUTH_R, message.getClientProfile(), ourClientProfilePayload, message.getX(),
                receiverECDHPublicKey, message.getA(), receiverDHPublicKey, message.senderInstanceTag.getValue(),
                message.receiverInstanceTag.getValue(), queryTag, senderAccountID, receiverAccountID);
        ringVerify(ourClientProfile.getLongTermPublicKey(), theirProfile.getLongTermPublicKey(), receiverECDHPublicKey,
                message.getSigma(), t);
    }
}
