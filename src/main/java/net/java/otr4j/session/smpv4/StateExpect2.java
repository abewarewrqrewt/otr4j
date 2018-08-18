package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x06;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x07;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.session.smpv4.SMPStatus.INPROGRESS;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static org.bouncycastle.util.Arrays.concatenate;

final class StateExpect2 implements SMPState {

    private final SecureRandom random;

    private final BigInteger secret;
    private final BigInteger a2;
    private final BigInteger a3;

    StateExpect2(@Nonnull final SecureRandom random, @Nonnull final BigInteger secret, @Nonnull final BigInteger a2,
            @Nonnull final BigInteger a3) {
        this.random = requireNonNull(random);
        this.secret = requireNonNull(secret);
        this.a2 = requireNonNull(a2);
        this.a3 = requireNonNull(a3);
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
        throw new SMPAbortException("Received SMP message 1 in StateExpect2.");
    }

    @Nonnull
    @Override
    public SMPMessage3 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage2 message) {
        // FIXME check input
        final BigInteger r4 = generateRandomValueInZq(this.random);
        final BigInteger r5 = generateRandomValueInZq(this.random);
        final BigInteger r6 = generateRandomValueInZq(this.random);
        final BigInteger r7 = generateRandomValueInZq(this.random);
        final Point g2 = message.g2b.multiply(this.a2);
        final Point g3 = message.g3b.multiply(this.a3);
        final Point pa = g3.multiply(r4);
        final Point g = basePoint();
        final BigInteger q = primeOrder();
        final BigInteger secretModQ = this.secret.mod(q);
        final Point qa = g.multiply(r4).add(g2.multiply(secretModQ));
        final BigInteger cp = hashToScalar(SMP_VALUE_0x06, concatenate(g3.multiply(r5).encode(),
                g.multiply(r5).add(g2.multiply(r6)).encode()));
        final BigInteger d5 = r5.subtract(r4.multiply(cp)).mod(q);
        final BigInteger d6 = r6.subtract(secretModQ.multiply(cp)).mod(q);
        final Point ra = qa.add(message.qb.negate()).multiply(a3);
        final BigInteger cr = hashToScalar(SMP_VALUE_0x07, concatenate(g.multiply(r7).encode(),
                qa.add(message.qb.negate()).multiply(r7).encode()));
        final BigInteger d7 = r7.subtract(a3.multiply(cr)).mod(q);
        context.setState(new StateExpect4(this.random));
        return new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
    }

    @Nonnull
    @Override
    public SMPMessage4 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage3 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 3 in StateExpect2.");
    }

    @Override
    public void process(@Nonnull final SMPContext context, @Nonnull final SMPMessage4 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 4 in StateExpect2.");
    }
}
