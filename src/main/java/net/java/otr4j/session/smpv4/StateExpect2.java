/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

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
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X03;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X04;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X05;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X06;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X07;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.generateRandomValueInZq;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static org.bouncycastle.util.Arrays.concatenate;

final class StateExpect2 implements SMPState {

    private static final Logger LOGGER = Logger.getLogger(StateExpect2.class.getName());

    private final SecureRandom random;

    private final Scalar secret;
    private final Scalar a2;
    private final Scalar a3;

    StateExpect2(@Nonnull final SecureRandom random, @Nonnull final Scalar secret, @Nonnull final Scalar a2,
            @Nonnull final Scalar a3) {
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
            @Nonnull final Scalar secret) throws SMPAbortException {
        context.setState(new StateExpect1(this.random, UNDECIDED));
        throw new SMPAbortException("Not in initial state. Aborting running SMP negotiation.");
    }

    @Nullable
    @Override
    public SMPMessage2 respondWithSecret(@Nonnull final SMPContext context, @Nonnull final String question,
            @Nonnull final Scalar secret) {
        // Given that this is an action by the local user, we don't see this as a violation of the protocol. Therefore,
        // we don't abort.
        LOGGER.log(Level.WARNING, "Requested to respond with secret answer, but no request is pending. Ignoring request.");
        return null;
    }

    @Nonnull
    @Override
    public SMPMessage3 process(@Nonnull final SMPContext context, @Nonnull final SMPMessage message)
            throws SMPAbortException {
        requireNonNull(context);
        requireNonNull(message);
        if (!(message instanceof SMPMessage2)) {
            throw new SMPAbortException("Received unexpected SMP message in StateExpect2.");
        }
        final SMPMessage2 smp2 = (SMPMessage2) message;
        if (!containsPoint(smp2.g2b) || !containsPoint(smp2.g3b) || !containsPoint(smp2.pb) || !containsPoint(smp2.qb)) {
            throw new SMPAbortException("Message failed verification.");
        }
        if (!smp2.c2.equals(hashToScalar(SMP_VALUE_0X03, multiplyByBase(smp2.d2).add(smp2.g2b.multiply(smp2.c2)).encode()))) {
            throw new SMPAbortException("Message failed verification.");
        }
        if (!smp2.c3.equals(hashToScalar(SMP_VALUE_0X04, multiplyByBase(smp2.d3).add(smp2.g3b.multiply(smp2.c3)).encode()))) {
            throw new SMPAbortException("Message failed verification.");
        }
        final Point g2 = smp2.g2b.multiply(this.a2);
        final Point g3 = smp2.g3b.multiply(this.a3);
        if (!smp2.cp.equals(hashToScalar(SMP_VALUE_0X05, concatenate(
                g3.multiply(smp2.d5).add(smp2.pb.multiply(smp2.cp)).encode(),
                multiplyByBase(smp2.d5).add(g2.multiply(smp2.d6)).add(smp2.qb.multiply(smp2.cp)).encode())))) {
            throw new SMPAbortException("Message failed verification.");
        }
        final Scalar r4 = generateRandomValueInZq(this.random);
        final Scalar r5 = generateRandomValueInZq(this.random);
        final Scalar r6 = generateRandomValueInZq(this.random);
        final Scalar r7 = generateRandomValueInZq(this.random);
        final Point pa = g3.multiply(r4);
        final Scalar q = primeOrder();
        final Scalar secretModQ = this.secret.mod(q);
        final Point qa = multiplyByBase(r4).add(g2.multiply(secretModQ));
        final Scalar cp = hashToScalar(SMP_VALUE_0X06, concatenate(g3.multiply(r5).encode(),
                multiplyByBase(r5).add(g2.multiply(r6)).encode()));
        final Scalar d5 = r5.subtract(r4.multiply(cp)).mod(q);
        final Scalar d6 = r6.subtract(secretModQ.multiply(cp)).mod(q);
        final Point ra = qa.add(smp2.qb.negate()).multiply(a3);
        final Scalar cr = hashToScalar(SMP_VALUE_0X07, concatenate(multiplyByBase(r7).encode(),
                qa.add(smp2.qb.negate()).multiply(r7).encode()));
        final Scalar d7 = r7.subtract(a3.multiply(cr)).mod(q);
        context.setState(new StateExpect4(this.random, this.a3, smp2.g3b, pa, smp2.pb, qa, smp2.qb));
        return new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
    }
}
