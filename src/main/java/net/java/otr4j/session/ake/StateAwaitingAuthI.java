package net.java.otr4j.session.ake;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthIMessage;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static java.util.Objects.requireNonNull;

final class StateAwaitingAuthI extends AbstractAuthState {

    private final String queryTag;
    private final ECDHKeyPair x;
    private final DHKeyPair a;

    StateAwaitingAuthI(@Nonnull final String queryTag, @Nonnull final ECDHKeyPair x, @Nonnull final DHKeyPair a) {
        this.queryTag = requireNonNull(queryTag);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) {
        if (!(message instanceof AuthIMessage)) {
            // FIXME how to handle unexpected message type?
            throw new IllegalStateException("Unexpected message type.");
        }
        // FIXME implement handling and transitioning.
        return null;
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
