/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OtrEngineHostUtil.finishedSessionMessage;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;

/**
 * Message state FINISHED. This message state is initiated through events
 * started from the initial message state PLAINTEXT (and transition through
 * ENCRYPTED).
 *
 * @author Danny van Heumen
 */
// FIXME write additional unit tests for StatePlaintext
final class StateFinished extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StateFinished.class.getName());

    StateFinished(@Nonnull final AuthState authState) {
        super(authState);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.FINISHED;
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in finished state.");
    }

    @Override
    @Nonnull
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available in finished state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in finished state.");
    }

    @Override
    @Nonnull
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        unencryptedMessageReceived(context.getHost(), context.getSessionID(), plainTextMessage.getCleanText());
        return super.handlePlainTextMessage(context, plainTextMessage);
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                // FIXME we suddenly transition out of FINISHED state (which may have entered only just now), now what do we do if user tries to send messages? We don't want them to suddenly be unencrypted.
                return handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final OtrCryptoException | ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
                return null;
            }
        }
        LOGGER.log(INFO, "We only expect to receive an Identity message. Ignoring message with messagetype: {0}",
                message.getType());
        return null;
    }

    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv4 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message);
        return null;
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv4 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message);
        return null;
    }

    @Override
    @Nullable
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final List<TLV> tlvs, final byte flags) {
        finishedSessionMessage(context.getHost(), context.getSessionID(), msgText);
        return null;
    }

    @Override
    public void end(@Nonnull final Context context) {
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }
}
