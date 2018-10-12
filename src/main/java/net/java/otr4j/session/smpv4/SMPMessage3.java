package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;

final class SMPMessage3 implements SMPMessage {

    final Point pa;

    final Point qa;

    final BigInteger cp;

    final BigInteger d5;

    final BigInteger d6;

    final Point ra;

    final BigInteger cr;

    final BigInteger d7;

    SMPMessage3(@Nonnull final Point pa, @Nonnull final Point qa, @Nonnull final BigInteger cp,
            @Nonnull final BigInteger d5, @Nonnull final BigInteger d6, @Nonnull final Point ra,
            @Nonnull final BigInteger cr, @Nonnull final BigInteger d7) {
        this.pa = requireNonNull(pa);
        this.qa = requireNonNull(qa);
        this.cp = requireNonNull(cp);
        this.d5 = requireNonNull(d5);
        this.d6 = requireNonNull(d6);
        this.ra = requireNonNull(ra);
        this.cr = requireNonNull(cr);
        this.d7 = requireNonNull(d7);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writePoint(this.pa).writePoint(this.qa).writeScalar(this.cp).writeScalar(this.d5).writeScalar(this.d6)
                .writePoint(this.ra).writeScalar(this.cr).writeScalar(this.d7);
    }
}
