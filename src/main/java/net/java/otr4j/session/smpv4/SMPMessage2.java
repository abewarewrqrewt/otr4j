package net.java.otr4j.session.smpv4;

import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;

final class SMPMessage2 implements OtrEncodable {

    final Point g2b;

    final BigInteger c2;

    final BigInteger d2;

    final Point g3b;

    final BigInteger c3;

    final BigInteger d3;

    final Point pb;

    final Point qb;

    final BigInteger cp;

    final BigInteger d5;

    final BigInteger d6;

    SMPMessage2(@Nonnull final Point g2b, @Nonnull final BigInteger c2, @Nonnull final BigInteger d2,
            @Nonnull final Point g3b, @Nonnull final BigInteger c3, @Nonnull final BigInteger d3,
            @Nonnull final Point pb, @Nonnull final Point qb, @Nonnull final BigInteger cp,
            @Nonnull final BigInteger d5, @Nonnull final BigInteger d6) {
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
        out.writePoint(this.g2b).writeBigInt(this.c2).writeBigInt(this.d2).writePoint(this.g3b).writeBigInt(this.c3)
                .writeBigInt(this.d3).writePoint(this.pb).writePoint(this.qb).writeBigInt(this.cp).writeBigInt(this.d5)
                .writeBigInt(this.d6);
    }
}
