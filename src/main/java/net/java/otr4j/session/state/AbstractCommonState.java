/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;

import java.security.SecureRandom;
import java.util.logging.Logger;

import static net.java.otr4j.api.OtrEngineHostUtil.showError;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.IdentityMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;

abstract class AbstractCommonState extends AbstractOTR4State {

    private static final Logger LOGGER = Logger.getLogger(AbstractCommonState.class.getName());

    AbstractCommonState(@Nonnull final AuthState authState) {
        super(authState);
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        return plainTextMessage.getCleanText();
    }

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage)
            throws OtrException {
        showError(context.getHost(), context.getSessionID(), errorMessage.error);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage message)
            throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
            throws OtrException {
        if ((message.getFlags() & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    @Nonnull
    AbstractEncodedMessage handleIdentityMessage(@Nonnull final Context context, @Nonnull final IdentityMessage message)
            throws OtrCryptoException, ValidationException {
        final ClientProfile theirClientProfile = message.getClientProfile().validate();
        validate(message, theirClientProfile);
        final ClientProfilePayload profile = context.getClientProfilePayload();
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final String queryTag = context.getQueryTag();
        final byte[] t = encode(AUTH_R, profile, message.getClientProfile(), x.getPublicKey(), message.getY(),
                a.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
                context.getReceiverInstanceTag().getValue(), queryTag, sessionID.getAccountID(),
                sessionID.getUserID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, longTermKeyPair,
                theirClientProfile.getForgingKey(), longTermKeyPair.getPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profile, x.getPublicKey(), a.getPublicKey(), sigma);
        context.transition(this, new StateAwaitingAuthI(getAuthState(), queryTag, x, a, message.getY(), message.getB(),
                profile, message.getClientProfile()));
        return authRMessage;
    }
}
