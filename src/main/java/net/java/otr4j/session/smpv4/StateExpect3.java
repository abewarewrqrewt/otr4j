package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x08;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.session.smpv4.SMPStatus.SUCCEEDED;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static org.bouncycastle.util.Arrays.concatenate;

final class StateExpect3 implements SMPState {

    private final SecureRandom random;

    private final Point qb;
    private final BigInteger b3;

    StateExpect3(@Nonnull final SecureRandom random, @Nonnull final Point qb, @Nonnull final BigInteger b3) {
        this.random = requireNonNull(random);
        this.qb = requireNonNull(qb);
        this.b3 = requireNonNull(b3);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return SMPStatus.INPROGRESS;
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
        throw new SMPAbortException("Received SMP message 1 in StateExpect3.");
    }

    @Nonnull
    @Override
    public SMPMessage3 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage2 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 2 in StateExpect3.");
    }

    @Nonnull
    @Override
    public SMPMessage4 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage3 message) {
        // FIXME check input
        final BigInteger r7 = generateRandomValueInZq(this.random);
        final Point rb = message.qa.add(this.qb.negate()).multiply(this.b3);
        final Point g = basePoint();
        final BigInteger cr = hashToScalar(SMP_VALUE_0x08, concatenate(g.multiply(r7).encode(),
                message.qa.add(this.qb.negate()).multiply(r7).encode()));
        final BigInteger q = primeOrder();
        final BigInteger d7 = r7.subtract(this.b3.multiply(cr)).mod(q);
        context.setState(new StateExpect1(this.random, SUCCEEDED));
        return new SMPMessage4(rb, cr, d7);
    }

    @Override
    public void process(@Nonnull final SMPContext context, @Nonnull final SMPMessage4 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 4 in StateExpect3.");
    }
}
