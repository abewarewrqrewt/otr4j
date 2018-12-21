/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * Class representing OTR Type-Length-Value tuples.
 */
//FIXME consider going back to public final fields such that getter is unnecessary and PMD warning is mitigated.
@SuppressWarnings("PMD.MethodReturnsInternalArray")
public final class TLV {

    /**
     * Empty array, for efficient reuse.
     */
    public static final byte[] EMPTY_BODY = new byte[0];

    /**
     * This is just padding for the encrypted message, and should be ignored.
     */
    public static final int PADDING = 0;
    /**
     * The sender has thrown away his OTR session keys with you.
     */
    public static final int DISCONNECTED = 0x0001;

    private final int type;
    private final byte[] value;

    /**
     * Constructor for the TLV.
     *
     * @param type  the type
     * @param value the value body (optional)
     */
    public TLV(final int type, @Nonnull final byte[] value) {
        this.type = type;
        this.value = Objects.requireNonNull(value);
    }

    /**
     * Get the type.
     *
     * @return type value
     */
    public int getType() {
        return type;
    }

    /**
     * Get the TLV embedded value.
     *
     * @return Value as byte-array.
     */
    @Nonnull
    public byte[] getValue() {
        return value;
    }
}
