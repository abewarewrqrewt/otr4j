package net.java.otr4j.io;

import javax.annotation.Nonnull;

public final class OtrEncodables {

    @Nonnull
    public static byte[] encode(@Nonnull final OtrEncodable encodable) {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            encodable.writeTo(out);
            return out.toByteArray();
        }
    }
}
