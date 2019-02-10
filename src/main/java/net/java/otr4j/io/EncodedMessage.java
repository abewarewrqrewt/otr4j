/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.InstanceTag;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Encoded message class that contains the common OTR header fields and the raw payload.
 */
public final class EncodedMessage implements Message {

    /**
     * Protocol version.
     */
    public final int version;

    /**
     * Message type identifier.
     */
    public final int type;

    /**
     * Sender tag.
     */
    public final InstanceTag senderTag;

    /**
     * Receiver tag.
     */
    public final InstanceTag receiverTag;

    /**
     * OTR-encoded payload of the message, intended for subsequent parsing.
     */
    public final OtrInputStream payload;

    /**
     * Constructor for the encoded message.
     *
     * @param version     the protocol version
     * @param type        the message type identifier
     * @param senderTag   the sender instance tag
     * @param receiverTag the receiver instance tag
     * @param payload     the OTR-encoded payload
     */
    public EncodedMessage(final int version, final int type, @Nonnull final InstanceTag senderTag,
            @Nonnull final InstanceTag receiverTag, @Nonnull final OtrInputStream payload) {
        this.version = version;
        this.type = type;
        this.senderTag = requireNonNull(senderTag);
        this.receiverTag = requireNonNull(receiverTag);
        this.payload = requireNonNull(payload);
    }
}
