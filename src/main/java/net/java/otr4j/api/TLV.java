/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Class representing OTR Type-Length-Value tuples.
 */
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

    /**
     * The TLV type
     */
    public final int type;

    /**
     * The TLV length and value.
     */
    public final byte[] value;

    /**
     * Constructor for the TLV.
     *
     * @param type  the type
     * @param value the value body (optional)
     */
    public TLV(final int type, @Nonnull final byte[] value) {
        this.type = type;
        this.value = requireNonNull(value);
    }
}
