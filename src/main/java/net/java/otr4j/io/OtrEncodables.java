package net.java.otr4j.io;

import javax.annotation.Nonnull;

/**
 * Utilities for {@link OtrEncodable}.
 */
public final class OtrEncodables {

    private OtrEncodables() {
        // No need to instantiate utility class.
    }

    /**
     * Encode provided {@link OtrEncodable} into OTR-encoded format.
     *
     * @param encodable the encodable
     * @return Returns byte-array representing OTR-encoded encodable.
     */
    @Nonnull
    public static byte[] encode(@Nonnull final OtrEncodable encodable) {
        final OtrOutputStream out = new OtrOutputStream();
        encodable.writeTo(out);
        return out.toByteArray();
    }
}
