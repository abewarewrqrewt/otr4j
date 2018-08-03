package net.java.otr4j.io;

import javax.annotation.Nonnull;

public final class OtrEncodables {

    private OtrEncodables() {
        // No need to instantiate utility class.
    }

    @Nonnull
    public static byte[] encode(@Nonnull final OtrEncodable encodable) {
        final OtrOutputStream out = new OtrOutputStream();
        encodable.writeTo(out);
        return out.toByteArray();
    }
}
