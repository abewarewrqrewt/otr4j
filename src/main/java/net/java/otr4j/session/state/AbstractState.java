/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHostUtil;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Abstract base implementation for session state implementations.
 *
 * @author Danny van Heumen
 */
abstract class AbstractState implements State {

    static final String DEFAULT_REPLY_UNREADABLE_MESSAGE = "This message cannot be read.";

    private static final Logger LOGGER = Logger.getLogger(AbstractState.class.getName());

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        OtrEngineHostUtil.showError(context.getHost(), this.getSessionID(), errorMessage.error);
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrCryptoException {
        context.setState(new StateEncrypted3(context, params));
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrException {
        final StateEncrypted4 encrypted = new StateEncrypted4(context, params);
        context.setState(encrypted);
        if (params.getInitializationComponent() == SecurityParameters4.Component.THEIRS) {
            LOGGER.log(Level.FINE, "We initialized THEIR component of the Double Ratchet, so it is complete. Sending heartbeat message.");
            // TODO this is not a formal heartbeat message because we do not set the ignoreUnreadable flag.
            context.injectMessage(encrypted.transformSending(context, "", Collections.<TLV>emptyList()));
        } else {
            LOGGER.log(Level.FINE, "We initialized OUR component of the Double Ratchet. We are still missing the other party's public key material, hence we cannot send messages yet. Now we wait to receive a message from the other party.");
        }
    }
}
