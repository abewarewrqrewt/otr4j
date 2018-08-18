package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.TLV;

import javax.annotation.Nonnull;

final class SMPMessageParser {

    private SMPMessageParser() {
        // No need to instantiate utility class.
    }

    static void parse(@Nonnull final TLV tlv) {
        switch (tlv.getType()) {
        case TLV.SMP1:
        case TLV.SMP2:
        case TLV.SMP3:
        case TLV.SMP4:
        case TLV.SMP_ABORT:
        default:
            throw new IllegalArgumentException("No other TLV type can be processed as SMP message.");
        }
    }
}
