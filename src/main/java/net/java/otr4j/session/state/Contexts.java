/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.io.ErrorMessage;

import javax.annotation.Nonnull;

import static net.java.otr4j.api.OtrEngineHosts.getReplyForUnreadableMessage;
import static net.java.otr4j.api.OtrEngineHosts.unreadableMessageReceived;

/**
 * Utility class for Context interface.
 */
public final class Contexts {

    private Contexts() {
        // No need to instantiate utility class.
    }

    /**
     * Signal both the local user and the remote party that a message is received that was unreadable.
     *
     * @param context    the context instance
     * @param identifier the error identifier for predefined errors defined by OTRv4 or empty-string for not predefined.
     * @param message    the textual error message.
     * @throws OtrException In case of failure to inject the remote message into the chat transport.
     */
    public static void signalUnreadableMessage(@Nonnull final Context context, @Nonnull final String identifier,
            @Nonnull final String message) throws OtrException {
        final OtrEngineHost host = context.getHost();
        final SessionID sessionID = context.getSessionID();
        unreadableMessageReceived(host, sessionID);
        final String replymsg = getReplyForUnreadableMessage(host, sessionID, message);
        context.injectMessage(new ErrorMessage(identifier, replymsg));
    }
}
