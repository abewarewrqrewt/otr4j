package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP1;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP2;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP3;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP4;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP_ABORT;

final class SMPMessages {

    private SMPMessages() {
        // No need to instantiate utility class.
    }

    static SMPMessage parse(@Nonnull final TLV tlv) throws ProtocolException, OtrCryptoException {
        final OtrInputStream in = new OtrInputStream(tlv.getValue());
        switch (tlv.getType()) {
        case SMP1: {
            final String question;
            try {
                question = new String(in.readData(), UTF_8);
            } catch (final OtrInputStream.UnsupportedLengthException e) {
                throw new ProtocolException("The question for SMP negotiation is too large. The message may have been damaged/malformed.");
            }
            final Point g2a = in.readPoint();
            final BigInteger c2 = in.readScalar();
            final BigInteger d2 = in.readScalar();
            final Point g3a = in.readPoint();
            final BigInteger c3 = in.readScalar();
            final BigInteger d3 = in.readScalar();
            return new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
        }
        case SMP2: {
            final Point g2b = in.readPoint();
            final BigInteger c2 = in.readScalar();
            final BigInteger d2 = in.readScalar();
            final Point g3b = in.readPoint();
            final BigInteger c3 = in.readScalar();
            final BigInteger d3 = in.readScalar();
            final Point pb = in.readPoint();
            final Point qb = in.readPoint();
            final BigInteger cp = in.readScalar();
            final BigInteger d5 = in.readScalar();
            final BigInteger d6 = in.readScalar();
            return new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        }
        case SMP3: {
            final Point pa = in.readPoint();
            final Point qa = in.readPoint();
            final BigInteger cp = in.readScalar();
            final BigInteger d5 = in.readScalar();
            final BigInteger d6 = in.readScalar();
            final Point ra = in.readPoint();
            final BigInteger cr = in.readScalar();
            final BigInteger d7 = in.readScalar();
            return new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        }
        case SMP4: {
            final Point rb = in.readPoint();
            final BigInteger cr = in.readScalar();
            final BigInteger d7 = in.readScalar();
            return new SMPMessage4(rb, cr, d7);
        }
        case SMP_ABORT:
            throw new IllegalStateException("SMP_Abort (TLV 6) should not be processed as SMP message, but instead handled outside of the SMP logic.");
        default:
            throw new IllegalArgumentException("No other TLV type can be processed as SMP message: " + tlv.getType());
        }
    }
}
