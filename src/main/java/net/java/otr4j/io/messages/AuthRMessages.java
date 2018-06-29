package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.ClientProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.io.messages.MysteriousT4.encode;

/**
 * Utility class for AuthRMessage. (Auth-R messages)
 */
// FIXME write unit tests
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
    // TODO make sure that sender and receiver instance tags are verified prior to arriving here!
    public static void validate(@Nonnull final AuthRMessage message, @Nonnull final ClientProfilePayload ourClientProfilePayload,
                                @Nonnull final String senderAccountID, @Nonnull final String receiverAccountID,
                                @Nonnull final Point receiverECDHPublicKey, @Nonnull final BigInteger receiverDHPublicKey,
                                @Nonnull final String queryTag) throws OtrCryptoException, ValidationException {
        if (message.getType() != AuthRMessage.MESSAGE_AUTH_R) {
            throw new IllegalStateException("Auth-R message should not have any other type than 0x91.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Auth-R message should not have any other protocol version than 4.");
        }
        // FIXME Check that the receiver's instance tag matches your sender's instance tag. (Really needed? I would expect this to happen earlier.)
        verifyECDHPublicKey(message.getX());
        verifyDHPublicKey(message.getA());
        final byte[] t = encode(message.getClientProfile(), ourClientProfilePayload, message.getX(),
            receiverECDHPublicKey, message.getA(), receiverDHPublicKey, message.senderInstanceTag,
            message.receiverInstanceTag, queryTag, senderAccountID, receiverAccountID);
        final ClientProfile theirProfile = message.getClientProfile().validate();
        if (theirProfile.getInstanceTag().getValue() != message.senderInstanceTag) {
            throw new ValidationException("The message sender's instance tag is different from the client profile's instance tag.");
        }
        // TODO how should we handle the case where our own client profile is not valid (anymore)?
        final ClientProfile ourClientProfile = ourClientProfilePayload.validate();
        // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, Y}, t)."
        ringVerify(theirProfile.getLongTermPublicKey(), ourClientProfile.getLongTermPublicKey(), receiverECDHPublicKey,
            message.getSigma(), t);
    }
}
