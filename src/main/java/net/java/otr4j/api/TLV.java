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
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    public static final int SMP1 = 0x0002;
    public static final int SMP2 = 0x0003;
    public static final int SMP3 = 0x0004;
    public static final int SMP4 = 0x0005;
    public static final int SMP_ABORT = 0x0006;
    /**
     * Like SMP1, but there's a question for the buddy at the beginning.
     */
    public static final int SMP1Q = 0x0007;
    /**
     * TLV 8 notifies the recipient to use the extra symmetric key to set up an
     * out-of-band encrypted connection.
     *
     * Payload:
     *  - 4-byte indication of what to use it for, e.g. file transfer, voice
     *    encryption, ...
     *  - undefined, free for use. Subsequent data might be the file name of
     *    your confidential file transfer.
     *
     * WARNING! You should NEVER send the extra symmetric key as payload inside
     * the TLV record. The recipient can already generate the extra symmetric
     * key.
     */
    public static final int USE_EXTRA_SYMMETRIC_KEY = 0x0008;

    private final int type;
    private final byte[] value;

    public TLV(final int type, @Nonnull final byte[] value) {
        this.type = type;
        this.value = Objects.requireNonNull(value);
    }

    public int getType() {
        return type;
    }

    @Nonnull
    public byte[] getValue() {
        return value;
    }
}
