package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X01;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X02;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X03;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X04;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X05;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.generateRandomValueInZq;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * StateExpect1 is the initial state for SMP.
 * <p>
 * StateExpect1 exists of 2 variants, in order of occurrence:
 * <ol>
 * <li>StateExpect1 without message: initial state, we receive the initiation message and given that we have not yet
 * acquired the secret from the local user, we can only request the secret and wait.</li>
 * <li>StateExpect1 with message: we are remembering the message up to the moment where the user provides us with
 * the secret. As soon as the secret answer is provided, we continue processing the remembered initiation message.
 * </li>
 * </ol>
 */
final class StateExpect1 implements SMPState {

    private static final Logger LOGGER = Logger.getLogger(StateExpect1.class.getName());

    /**
     * The SecureRandom instance.
     */
    private final SecureRandom random;

    /**
     * The current SMP status.
     */
    private final SMPStatus status;

    /**
     * The previously received SMPMessage1. This field exists to remember the initiation message in the time we are
     * requesting the local user to provide his answer to the posed question.
     */
    private final SMPMessage1 message;

    StateExpect1(@Nonnull final SecureRandom random, @Nonnull final SMPStatus status) {
        this.random = requireNonNull(random);
        this.status = requireNonNull(status);
        this.message = null;
    }

    private StateExpect1(@Nonnull final SecureRandom random, @Nonnull final SMPStatus status,
            @Nonnull final SMPMessage1 message) {
        this.random = requireNonNull(random);
        this.status = requireNonNull(status);
        this.message = requireNonNull(message);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return this.status;
    }

    @Nonnull
    @Override
    public SMPMessage1 initiate(@Nonnull final SMPContext context, @Nonnull final String question,
            @Nonnull final Scalar secret) {
        requireNonNull(context);
        final Scalar a2 = generateRandomValueInZq(this.random);
        final Scalar a3 = generateRandomValueInZq(this.random);
        final Scalar r2 = generateRandomValueInZq(this.random);
        final Scalar r3 = generateRandomValueInZq(this.random);
        final Point g2a = multiplyByBase(a2);
        final Point g3a = multiplyByBase(a3);
        final Scalar q = primeOrder();
        final Scalar c2 = hashToScalar(SMP_VALUE_0X01, multiplyByBase(r2).encode());
        final Scalar d2 = r2.subtract(a2.multiply(c2)).mod(q);
        final Scalar c3 = hashToScalar(SMP_VALUE_0X02, multiplyByBase(r3).encode());
        final Scalar d3 = r3.subtract(a3.multiply(c3)).mod(q);
        context.setState(new StateExpect2(this.random, secret, a2, a3));
        return new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
    }

    @Nullable
    @Override
    public SMPMessage2 respondWithSecret(@Nonnull final SMPContext context, @Nonnull final String question,
            @Nonnull final Scalar secret) {
        requireNonNull(context);
        if (this.message == null) {
            LOGGER.log(Level.WARNING, "The answer to the SMP question is provided, but no message is available. Ignoring answer.");
            return null;
        }
        if (!question.equals(this.message.question)) {
            LOGGER.log(Level.INFO, "The question does not match the question in the remembered message. The request-for-secret is probably outdated. Ignoring answer.");
            return null;
        }
        final Scalar b2 = generateRandomValueInZq(this.random);
        final Scalar b3 = generateRandomValueInZq(this.random);
        final Scalar r2 = generateRandomValueInZq(this.random);
        final Scalar r3 = generateRandomValueInZq(this.random);
        final Scalar r4 = generateRandomValueInZq(this.random);
        final Scalar r5 = generateRandomValueInZq(this.random);
        final Scalar r6 = generateRandomValueInZq(this.random);
        final Point g2b = multiplyByBase(b2);
        final Point g3b = multiplyByBase(b3);
        final Scalar q = primeOrder();
        final Scalar c2 = hashToScalar(SMP_VALUE_0X03, multiplyByBase(r2).encode());
        final Scalar d2 = r2.subtract(b2.multiply(c2)).mod(q);
        final Scalar c3 = hashToScalar(SMP_VALUE_0X04, multiplyByBase(r3).encode());
        final Scalar d3 = r3.subtract(b3.multiply(c3)).mod(q);
        final Point g2 = this.message.g2a.multiply(b2);
        final Point g3 = this.message.g3a.multiply(b3);
        final Point pb = g3.multiply(r4);
        final Point qb = multiplyByBase(r4).add(g2.multiply(secret.mod(q)));
        final Scalar cp = hashToScalar(SMP_VALUE_0X05, concatenate(g3.multiply(r5).encode(),
                multiplyByBase(r5).add(g2.multiply(r6)).encode()));
        final Scalar d5 = r5.subtract(r4.multiply(cp)).mod(q);
        final Scalar d6 = r6.subtract(secret.mod(q).multiply(cp)).mod(q);
        context.setState(new StateExpect3(this.random, pb, qb, b3, this.message.g3a, g2, g3));
        return new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
    }

    @Nullable
    @Override
    public SMPMessage process(@Nonnull final SMPContext context, @Nonnull final SMPMessage message)
            throws SMPAbortException {
        requireNonNull(context);
        requireNonNull(message);
        if (!(message instanceof SMPMessage1)) {
            throw new SMPAbortException("Received unexpected SMP message in StateExpect1.");
        }
        final SMPMessage1 smp1 = (SMPMessage1) message;
        if (!containsPoint(smp1.g2a) || !containsPoint(smp1.g3a)) {
            throw new SMPAbortException("g2a or g3a failed verification.");
        }
        if (!smp1.c2.equals(hashToScalar(SMP_VALUE_0X01, multiplyByBase(smp1.d2).add(smp1.g2a.multiply(smp1.c2))
                .encode()))) {
            throw new SMPAbortException("c2 failed verification.");
        }
        if (!smp1.c3.equals(hashToScalar(SMP_VALUE_0X02, multiplyByBase(smp1.d3).add(smp1.g3a.multiply(smp1.c3))
                .encode()))) {
            throw new SMPAbortException("c3 failed verification.");
        }
        context.requestSecret(smp1.question);
        context.setState(new StateExpect1(this.random, this.status, smp1));
        return null;
    }
}
