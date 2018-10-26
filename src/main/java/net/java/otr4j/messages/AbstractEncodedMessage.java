/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.annotation.OverridingMethodsMustInvokeSuper;

import static java.util.Objects.requireNonNull;

/**
 * Abstract class representing base for encoded messages.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public abstract class AbstractEncodedMessage implements Message, OtrEncodable {

    /**
     * Protocol version.
     */
    public final int protocolVersion;

    /**
     * Sender instance tag.
     */
    public final InstanceTag senderInstanceTag;

    /**
     * Receiver instance tag.
     */
    public final InstanceTag receiverInstanceTag;

    AbstractEncodedMessage(final int protocolVersion, @Nonnull final InstanceTag senderInstanceTag,
            @Nonnull final InstanceTag receiverInstanceTag) {
        this.protocolVersion = protocolVersion;
        this.senderInstanceTag = requireNonNull(senderInstanceTag);
        this.receiverInstanceTag = requireNonNull(receiverInstanceTag);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + this.protocolVersion;
        hash = 97 * hash + this.senderInstanceTag.hashCode();
        hash = 97 * hash + this.receiverInstanceTag.hashCode();
        return hash;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AbstractEncodedMessage other = (AbstractEncodedMessage) obj;
        if (this.protocolVersion != other.protocolVersion) {
            return false;
        }
        if (!this.senderInstanceTag.equals(other.senderInstanceTag)) {
            return false;
        }
        return this.receiverInstanceTag.equals(other.receiverInstanceTag);
    }

    @OverridingMethodsMustInvokeSuper
    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        // Start writing common header of encoded messages.
        writer.writeShort(this.protocolVersion);
        writer.writeByte(getType());
        switch (this.protocolVersion) {
        case OTRv.TWO:
            // skipping serializing instance tags
            break;
        case OTRv.THREE:
        case OTRv.FOUR:
            writer.writeInstanceTag(this.senderInstanceTag);
            writer.writeInstanceTag(this.receiverInstanceTag);
            break;
        default:
            throw new UnsupportedOperationException("Unsupported protocol version.");
        }
    }

    /**
     * Get encoded message type (integer value type representation).
     *
     * @return the integer value of the type
     */
    public abstract int getType();
}
