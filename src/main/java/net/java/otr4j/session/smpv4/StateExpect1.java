package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.OtrCryptoEngine4;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x01;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x02;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Ed448.modulus;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static org.bouncycastle.util.Arrays.concatenate;

final class StateExpect1 implements SMPState {

    private final SMPStatus status;
    private final SecureRandom random;

    StateExpect1(@Nonnull final SecureRandom random, @Nonnull final SMPStatus status) {
        this.random = requireNonNull(random);
        this.status = requireNonNull(status);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return this.status;
    }

    @Nonnull
    @Override
    public SMPMessage1 initiate(@Nonnull final SMPContext context, @Nonnull final String question, @Nonnull final BigInteger secret) {
        final BigInteger a2 = generateRandomValueInZq(this.random);
        final BigInteger a3 = generateRandomValueInZq(this.random);
        final BigInteger r2 = generateRandomValueInZq(this.random);
        final BigInteger r3 = generateRandomValueInZq(this.random);
        final Point g = basePoint();
        final Point g2a = g.multiply(a2);
        final Point g3a = g.multiply(a3);
        final BigInteger q = modulus();
        final BigInteger c2 = hashToScalar(SMP_VALUE_0x01, g.multiply(r2).encode());
        final BigInteger d2 = r2.subtract(a2.multiply(c2)).mod(q);
        final BigInteger c3 = hashToScalar(SMP_VALUE_0x02, g.multiply(r3).encode());
        final BigInteger d3 = r3.subtract(a3.multiply(c3)).mod(q);
        context.setState(new StateExpect2(this.random, secret, a2, a3));
        return new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
    }

    @Nonnull
    @Override
    public SMPMessage2 process(@Nonnull final SMPContext context, @Nonnull final BigInteger secret, @Nonnull final SMPMessage1 message) {
        // FIXME check input
        final BigInteger b2 = generateRandomValueInZq(this.random);
        final BigInteger b3 = generateRandomValueInZq(this.random);
        final BigInteger r2 = generateRandomValueInZq(this.random);
        final BigInteger r3 = generateRandomValueInZq(this.random);
        final BigInteger r4 = generateRandomValueInZq(this.random);
        final BigInteger r5 = generateRandomValueInZq(this.random);
        final BigInteger r6 = generateRandomValueInZq(this.random);
        final Point g = basePoint();
        final Point g2b = g.multiply(b2);
        final Point g3b = g.multiply(b3);
        final BigInteger q = primeOrder();
        final BigInteger c2 = hashToScalar(OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x03, g.multiply(r2).encode());
        final BigInteger d2 = r2.subtract(b2.multiply(c2)).mod(q);
        final BigInteger c3 = hashToScalar(OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x04, g.multiply(r3).encode());
        final BigInteger d3 = r3.subtract(b3.multiply(c3)).mod(q);
        final Point g2 = message.g2a.multiply(b2);
        final Point g3 = message.g3a.multiply(b3);
        final Point pb = g3.multiply(r4);
        final Point qb = g.multiply(r4).add(g2.multiply(secret.mod(q)));
        final BigInteger cp = hashToScalar(OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x05, concatenate(g3.multiply(r5).encode(),
                g.multiply(r5).add(g2.multiply(r6)).encode()));
        final BigInteger d5 = r5.subtract(r4.multiply(cp)).mod(q);
        final BigInteger d6 = r6.subtract(secret.mod(q).multiply(cp)).mod(q);
        context.setState(new StateExpect3(this.random, qb, b3));
        return new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
    }

    @Nonnull
    @Override
    public SMPMessage3 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage2 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 2 in StateExpect1.");
    }

    @Nonnull
    @Override
    public SMPMessage4 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage3 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 3 in StateExpect1.");
    }

    @Override
    public void process(@Nonnull final SMPContext context, @Nonnull final SMPMessage4 message)
            throws SMPAbortException {
        throw new SMPAbortException("Received SMP message 4 in StateExpect1.");
    }
}
