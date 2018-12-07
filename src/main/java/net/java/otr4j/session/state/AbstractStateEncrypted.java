/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.logging.Logger;

abstract class AbstractStateEncrypted extends AbstractOTR4State implements StateEncrypted {

    @SuppressWarnings("PMD.LoggerIsNotStaticFinal")
    final Logger logger;

    AbstractStateEncrypted(@Nonnull final Context context, @Nonnull final AuthState authState) {
        super(authState);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
    }

    @Nonnull
    @Override
    public abstract AbstractEncodedMessage transformSending(@Nonnull final Context context, @Nonnull String msgText,
            @Nonnull List<TLV> tlvs, byte flags) throws OtrException;
}
