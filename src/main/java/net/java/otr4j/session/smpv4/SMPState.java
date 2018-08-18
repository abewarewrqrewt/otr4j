package net.java.otr4j.session.smpv4;

import javax.annotation.Nonnull;
import java.math.BigInteger;

interface SMPState {

    @Nonnull
    SMPStatus getStatus();

    @Nonnull
    SMPMessage1 initiate(@Nonnull SMPContext context, @Nonnull String question, @Nonnull BigInteger secret);

    @Nonnull
    SMPMessage2 process(@Nonnull SMPContext context, @Nonnull BigInteger secret, @Nonnull SMPMessage1 message) throws SMPAbortException;

    @Nonnull
    SMPMessage3 process(@Nonnull SMPContext context, @Nonnull SMPMessage2 message) throws SMPAbortException;

    @Nonnull
    SMPMessage4 process(@Nonnull SMPContext context, @Nonnull SMPMessage3 message) throws SMPAbortException;

    void process(@Nonnull SMPContext context, @Nonnull SMPMessage4 message) throws SMPAbortException;
}
