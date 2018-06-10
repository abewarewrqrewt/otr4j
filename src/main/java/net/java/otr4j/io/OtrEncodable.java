package net.java.otr4j.io;

import javax.annotation.Nonnull;

/**
 * Interface indicating this type is OTR-encodable.
 */
public interface OtrEncodable {

    /**
     * OTR-encode content and write to provided OtrOutputStream.
     *
     * @param out The destination OTR output stream.
     */
    void writeTo(@Nonnull OtrOutputStream out);
}
