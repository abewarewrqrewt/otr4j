package net.java.otr4j.session.state;

import javax.annotation.Nonnull;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.io.messages.ErrorMessage;

abstract class AbstractState implements State {

    protected static final String DEFAULT_REPLY_UNREADABLE_MESSAGE = "This message cannot be read.";

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        // TODO consider moving the 'handleError' implementation to the concrete states, as the Encrypted state is the only state we would expect to call this method.
        OtrEngineHostUtil.showError(context.getHost(), this.getSessionID(), errorMessage.error);
    }
}
