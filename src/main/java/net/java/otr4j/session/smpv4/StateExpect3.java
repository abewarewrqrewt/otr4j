package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x06;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x07;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0x08;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.session.smpv4.SMPStatus.SUCCEEDED;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static org.bouncycastle.util.Arrays.concatenate;

final class StateExpect3 implements SMPState {

    private static final Logger LOGGER = Logger.getLogger(StateExpect3.class.getName());

    private final SecureRandom random;

    private final Point pb;
    private final Point qb;
    private final BigInteger b3;
    private final Point g3a;
    private final Point g2;
    private final Point g3;

    StateExpect3(@Nonnull final SecureRandom random, @Nonnull final Point pb, @Nonnull final Point qb,
            @Nonnull final BigInteger b3, @Nonnull final Point g3a, @Nonnull final Point g2, @Nonnull final Point g3) {
        this.random = requireNonNull(random);
        this.pb = requireNonNull(pb);
        this.qb = requireNonNull(qb);
        this.b3 = requireNonNull(b3);
        this.g3a = requireNonNull(g3a);
        this.g2 = requireNonNull(g2);
        this.g3 = requireNonNull(g3);
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

    @Nullable
    @Override
    public SMPMessage2 respondWithSecret(@Nonnull final SMPContext context, @Nonnull final String question, @Nonnull final BigInteger secret) {
        // Given that this is an action by the local user, we don't see this as a violation of the protocol. Therefore,
        // we don't abort.
        LOGGER.log(Level.WARNING, "Requested to respond with secret answer, but no request is pending. Ignoring request.");
        return null;
    }

    @Nonnull
    @Override
    public SMPMessage process(@Nonnull final SMPContext context, @Nonnull final SMPMessage message)
            throws SMPAbortException {
        if (!(message instanceof SMPMessage3)) {
            throw new SMPAbortException("Received unexpected SMP message in StateExpect3.");
        }
        final SMPMessage3 smp3 = (SMPMessage3) message;
        if (!Ed448.contains(smp3.pa) || !Ed448.contains(smp3.qa) || !Ed448.contains(smp3.ra)) {
            throw new SMPAbortException("Message failed verification.");
        }
        final Point g = basePoint();
        if (!smp3.cp.equals(hashToScalar(SMP_VALUE_0x06, concatenate(
                this.g3.multiply(smp3.d5).add(smp3.pa.multiply(smp3.cp)).encode(),
                g.multiply(smp3.d5).add(g2.multiply(smp3.d6)).add(smp3.qa.multiply(smp3.cp)).encode())))) {
            throw new SMPAbortException("Message failed verification.");
        }
        if (!smp3.cr.equals(hashToScalar(SMP_VALUE_0x07, concatenate(
                g.multiply(smp3.d7).add(g3a.multiply(smp3.cr)).encode(),
                smp3.qa.add(this.qb.negate()).multiply(smp3.d7).add(smp3.ra.multiply(smp3.cr)).encode())))) {
            throw new SMPAbortException("Message failed verification.");
        }
        // Verify if the zero-knowledge proof succeeds on our end.
        final Point rab = smp3.ra.multiply(this.b3);
        if (!rab.equals(smp3.pa.add(this.pb.negate()))) {
            throw new SMPAbortException("Final zero-knowledge proof failed.");
        }
        context.setState(new StateExpect1(this.random, SUCCEEDED));
        // Compose final message to other party.
        final Point rb = smp3.qa.add(this.qb.negate()).multiply(this.b3);
        final BigInteger r7 = generateRandomValueInZq(this.random);
        final BigInteger cr = hashToScalar(SMP_VALUE_0x08, concatenate(g.multiply(r7).encode(),
                smp3.qa.add(this.qb.negate()).multiply(r7).encode()));
        final BigInteger d7 = r7.subtract(this.b3.multiply(cr)).mod(primeOrder());
        return new SMPMessage4(rb, cr, d7);
    }
}
