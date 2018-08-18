package net.java.otr4j.session.smpv4;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.session.smpv4.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.smpv4.SMPStatus.SUCCEEDED;

final class StateExpect4 implements SMPState {

    private final SecureRandom random;

    StateExpect4(@Nonnull final SecureRandom random) {
        this.random = requireNonNull(random);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return INPROGRESS;
    }

    @Nonnull
    @Override
    public SMPMessage1 initiate(@Nonnull final SMPContext context, @Nonnull final String question,
            @Nonnull final BigInteger secret) {
        // FIXME implement SMP initiation in StateExpect1
        throw new UnsupportedOperationException("To be implemented");
    }

    @Nonnull
    @Override
    public SMPMessage2 process(@Nonnull final SMPContext context, @Nonnull final BigInteger secret,
            @Nonnull final SMPMessage1 message) throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 1 in StateExpect4.");
    }

    @Nonnull
    @Override
    public SMPMessage3 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage2 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 2 in StateExpect4.");
    }

    @Nonnull
    @Override
    public SMPMessage4 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage3 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 3 in StateExpect4.");
    }

    @Override
    public void process(@Nonnull final SMPContext context, @Nonnull final SMPMessage4 message) {
        // FIXME implement message 4 processing in StateExpect1
        context.setState(new StateExpect1(this.random, SUCCEEDED));
        throw new UnsupportedOperationException("To be implemented");
    }
}
