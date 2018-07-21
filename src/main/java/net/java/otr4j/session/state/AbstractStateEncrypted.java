package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.messages.AbstractEncodedMessage;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;

abstract class AbstractStateEncrypted extends AbstractState {

    final SessionID sessionID;

    final Logger logger;

    /**
     * OTR engine host.
     */
    final OtrEngineHost host;

    AbstractStateEncrypted(@Nonnull final SessionID sessionID, @Nonnull final OtrEngineHost host) {
        super();
        this.sessionID = requireNonNull(sessionID);
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.host = requireNonNull(host);
    }

    @Nonnull
    @Override
    public SessionID getSessionID() {
        return this.sessionID;
    }

    @Nonnull
    @Override
    public abstract AbstractEncodedMessage transformSending(@Nonnull Context context, @Nonnull String msgText, @Nonnull List<TLV> tlvs) throws OtrException;

    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, TLV.EMPTY_BODY);
        final AbstractEncodedMessage m = transformSending(context, "", Collections.singletonList(disconnectTlv));
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure
            // we transition to PLAINTEXT even if we have problems injecting the
            // message into the transport.
            context.setState(new StatePlaintext(this.sessionID));
        }
    }
}
