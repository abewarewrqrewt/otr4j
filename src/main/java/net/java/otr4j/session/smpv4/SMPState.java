package net.java.otr4j.session.smpv4;

import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;

interface SMPState {

    @Nonnull
    SMPStatus getStatus();

    @Nonnull
    SMPMessage1 initiate(@Nonnull SMPContext context, @Nonnull String question, @Nonnull BigInteger secret);

    @Nullable
    SMPMessage2 respondWithSecret(@Nonnull SMPContext context, @Nonnull String question, @Nonnull BigInteger secret);

    @Nullable
    SMPMessage process(@Nonnull SMPContext context, @Nonnull SMPMessage message) throws SMPAbortException;
}
