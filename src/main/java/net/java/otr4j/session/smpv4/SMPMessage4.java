package net.java.otr4j.session.smpv4;

import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;

final class SMPMessage4 implements OtrEncodable {

    final Point rb;

    final BigInteger cr;

    final BigInteger d7;

    SMPMessage4(@Nonnull final Point rb, @Nonnull final BigInteger cr, @Nonnull final BigInteger d7) {
        this.rb = requireNonNull(rb);
        this.cr = requireNonNull(cr);
        this.d7 = requireNonNull(d7);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writePoint(this.rb).writeBigInt(this.cr).writeBigInt(this.d7);
    }
}
