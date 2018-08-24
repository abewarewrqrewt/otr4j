package net.java.otr4j.session.smpv4;

import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

final class SMPMessage1 implements SMPMessage {

    final String question;

    final Point g2a;

    final BigInteger c2;

    final BigInteger d2;

    final Point g3a;

    final BigInteger c3;

    final BigInteger d3;

    SMPMessage1(@Nonnull final String question, @Nonnull final Point g2a, @Nonnull final BigInteger c2,
            @Nonnull final BigInteger d2, @Nonnull final Point g3a, @Nonnull final BigInteger c3,
            @Nonnull final BigInteger d3) {
        this.question = requireNonNull(question);
        this.g2a = requireNonNull(g2a);
        this.c2 = requireNonNull(c2);
        this.d2 = requireNonNull(d2);
        this.g3a = requireNonNull(g3a);
        this.c3 = requireNonNull(c3);
        this.d3 = requireNonNull(d3);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writeData(question.getBytes(UTF_8)).writePoint(this.g2a).writeScalar(this.c2).writeScalar(this.d2)
                .writePoint(this.g3a).writeScalar(this.c3).writeScalar(this.d3);
    }
}
