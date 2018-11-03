/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

final class SMPMessage3 implements SMPMessage {

    final Point pa;

    final Point qa;

    final Scalar cp;

    final Scalar d5;

    final Scalar d6;

    final Point ra;

    final Scalar cr;

    final Scalar d7;

    SMPMessage3(@Nonnull final Point pa, @Nonnull final Point qa, @Nonnull final Scalar cp, @Nonnull final Scalar d5,
            @Nonnull final Scalar d6, @Nonnull final Point ra, @Nonnull final Scalar cr, @Nonnull final Scalar d7) {
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
