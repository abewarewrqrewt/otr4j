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

    private final int version;
    private final int type;
    private final InstanceTag senderInstanceTag;
    private final InstanceTag receiverInstanceTag;
    private final OtrInputStream payload;

    // TODO consider making constructor public (would simplify code in EncodedMessageParser significantly)
    EncodedMessage(final int version, final int type, @Nonnull final InstanceTag senderInstanceTag,
            @Nonnull final InstanceTag receiverInstanceTag, @Nonnull final OtrInputStream payload) {
        this.version = version;
        this.type = type;
        this.senderInstanceTag = requireNonNull(senderInstanceTag);
        this.receiverInstanceTag = requireNonNull(receiverInstanceTag);
        this.payload = requireNonNull(payload);
    }

    /**
     * Protocol version to which the encoded message corresponds.
     *
     * @return protocol version
     */
    public int getVersion() {
        return version;
    }

    /**
     * The message type of the encoded message.
     *
     * @return message type
     */
    public int getType() {
        return type;
    }

    /**
     * The sender instance tag.
     *
     * @return sender instance tag
     */
    public InstanceTag getSenderTag() {
        return senderInstanceTag;
    }

    /**
     * The receiver instance tag.
     *
     * @return receiver instance tag
     */
    public InstanceTag getReceiverTag() {
        return receiverInstanceTag;
    }

    /**
     * The encoded message payload, i.e. the non-common part of the encoded message. Only the header, the common part of
     * all encoded messages, is parsed. The remaining content is provided as opaque blob for further processing.
     *
     * @return the payload of the encoded message
     */
    public OtrInputStream getPayload() {
        return payload;
    }
}
