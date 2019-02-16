/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
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
    public final InstanceTag senderTag;

    /**
     * Receiver instance tag.
     */
    public final InstanceTag receiverTag;

    AbstractEncodedMessage(final int protocolVersion, @Nonnull final InstanceTag senderTag,
            @Nonnull final InstanceTag receiverTag) {
        this.protocolVersion = protocolVersion;
        this.senderTag = requireNonNull(senderTag);
        this.receiverTag = requireNonNull(receiverTag);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + this.protocolVersion;
        hash = 97 * hash + this.senderTag.hashCode();
        hash = 97 * hash + this.receiverTag.hashCode();
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
        if (!(obj instanceof AbstractEncodedMessage)) {
            return false;
        }
        final AbstractEncodedMessage other = (AbstractEncodedMessage) obj;
        if (this.protocolVersion != other.protocolVersion) {
            return false;
        }
        if (!this.senderTag.equals(other.senderTag)) {
            return false;
        }
        return this.receiverTag.equals(other.receiverTag);
    }

    @OverridingMethodsMustInvokeSuper
    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        // Start writing common header of encoded messages.
        writer.writeShort(this.protocolVersion);
        writer.writeByte(getType());
        switch (this.protocolVersion) {
        case Version.TWO:
            // skipping serializing instance tags
            break;
        case Version.THREE: // fall-through intended
        case Version.FOUR:
            writer.writeInstanceTag(this.senderTag);
            writer.writeInstanceTag(this.receiverTag);
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

    @Override
    public String toString() {
        return "AbstractEncodedMessage{" + "protocolVersion=" + protocolVersion + ", senderTag=" + senderTag
                + ", receiverTag=" + receiverTag + '}';
    }
}
