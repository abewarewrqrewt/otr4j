package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

final class SMPMessage2 implements SMPMessage {

    final Point g2b;

    final Scalar c2;

    final Scalar d2;

    final Point g3b;

    final Scalar c3;

    final Scalar d3;

    final Point pb;

    final Point qb;

    final Scalar cp;

    final Scalar d5;

    final Scalar d6;

    SMPMessage2(@Nonnull final Point g2b, @Nonnull final Scalar c2, @Nonnull final Scalar d2, @Nonnull final Point g3b,
            @Nonnull final Scalar c3, @Nonnull final Scalar d3, @Nonnull final Point pb, @Nonnull final Point qb,
            @Nonnull final Scalar cp, @Nonnull final Scalar d5, @Nonnull final Scalar d6) {
        this.g2b = requireNonNull(g2b);
        this.c2 = requireNonNull(c2);
        this.d2 = requireNonNull(d2);
        this.g3b = requireNonNull(g3b);
        this.c3 = requireNonNull(c3);
        this.d3 = requireNonNull(d3);
        this.pb = requireNonNull(pb);
        this.qb = requireNonNull(qb);
        this.cp = requireNonNull(cp);
        this.d5 = requireNonNull(d5);
        this.d6 = requireNonNull(d6);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writePoint(this.g2b).writeScalar(this.c2).writeScalar(this.d2).writePoint(this.g3b).writeScalar(this.c3)
                .writeScalar(this.d3).writePoint(this.pb).writePoint(this.qb).writeScalar(this.cp).writeScalar(this.d5)
                .writeScalar(this.d6);
    }
}
