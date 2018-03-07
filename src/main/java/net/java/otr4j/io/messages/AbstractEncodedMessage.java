/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.io.IOException;

/**
 * 
 * @author George Politis
 * @author Danny van Heumen
 */
public abstract class AbstractEncodedMessage implements Message {

    public final int protocolVersion;

    public final int senderInstanceTag;

    public final int receiverInstanceTag;

    AbstractEncodedMessage(final int protocolVersion, final int senderInstanceTag, final int recipientInstanceTag) {
        this.protocolVersion = protocolVersion;
        this.senderInstanceTag = senderInstanceTag;
        this.receiverInstanceTag = recipientInstanceTag;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + this.protocolVersion;
        hash = 97 * hash + this.senderInstanceTag;
        hash = 97 * hash + this.receiverInstanceTag;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
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
        if (this.senderInstanceTag != other.senderInstanceTag) {
            return false;
        }
        if (this.receiverInstanceTag != other.receiverInstanceTag) {
            return false;
        }
        return true;
    }

    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        // Start writing common header of encoded messages.
        writer.writeShort(this.protocolVersion);
        writer.writeByte(getType());
        if (this.protocolVersion == Session.OTRv.THREE) {
            writer.writeInt(this.senderInstanceTag);
            writer.writeInt(this.receiverInstanceTag);
        }
    }

    public abstract int getType();
}
