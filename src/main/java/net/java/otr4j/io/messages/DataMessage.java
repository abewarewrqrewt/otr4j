/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import javax.annotation.Nonnull;

import javax.crypto.interfaces.DHPublicKey;

/**
 * OTRv2 encrypted data message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class DataMessage extends AbstractEncodedMessage {

    static final int MESSAGE_DATA = 0x03;

    public final int flags;
    public final int senderKeyID;
    public final int recipientKeyID;
    public final DHPublicKey nextDH;
    public final byte[] ctr;
    public final byte[] encryptedMessage;
    public final byte[] mac;
    public final byte[] oldMACKeys;

    public DataMessage(@Nonnull final MysteriousT t, @Nonnull final byte[] mac,
            @Nonnull final byte[] oldMacKeys, final int senderInstanceTag,
            final int receiverInstanceTag) {
        this(t.protocolVersion, t.flags, t.senderKeyID, t.recipientKeyID,
                t.nextDH, t.ctr, t.encryptedMessage, mac, oldMacKeys,
                senderInstanceTag, receiverInstanceTag);
    }

    public DataMessage(final int protocolVersion, final int flags, final int senderKeyID,
            final int recipientKeyID, @Nonnull final DHPublicKey nextDH,
            @Nonnull final byte[] ctr, @Nonnull final byte[] encryptedMessage,
            @Nonnull final byte[] mac, @Nonnull final byte[] oldMacKeys,
            final int senderInstanceTag, final int receiverInstanceTag) {
        super(protocolVersion, senderInstanceTag, receiverInstanceTag);
        this.flags = flags;
        this.senderKeyID = senderKeyID;
        this.recipientKeyID = recipientKeyID;
        this.nextDH = Objects.requireNonNull(nextDH);
        this.ctr = Objects.requireNonNull(ctr);
        this.encryptedMessage = Objects.requireNonNull(encryptedMessage);
        this.mac = Objects.requireNonNull(mac);
        this.oldMACKeys = Objects.requireNonNull(oldMacKeys);
    }

    public MysteriousT getT() {
        return new MysteriousT(protocolVersion, senderInstanceTag,
                receiverInstanceTag, flags, senderKeyID,
                recipientKeyID, nextDH, ctr, encryptedMessage);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(ctr);
        result = prime * result + Arrays.hashCode(encryptedMessage);
        result = prime * result + flags;
        result = prime * result + Arrays.hashCode(mac);
        result = prime * result + ((nextDH == null) ? 0 : nextDH.hashCode());
        result = prime * result + Arrays.hashCode(oldMACKeys);
        result = prime * result + recipientKeyID;
        result = prime * result + senderKeyID;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        DataMessage other = (DataMessage) obj;
        if (!Arrays.equals(ctr, other.ctr)) {
            return false;
        }
        if (!Arrays.equals(encryptedMessage, other.encryptedMessage)) {
            return false;
        }
        if (flags != other.flags) {
            return false;
        }
        if (!Arrays.equals(mac, other.mac)) {
            return false;
        }
        if (nextDH == null) {
            if (other.nextDH != null) {
                return false;
            }
        } else if (!nextDH.equals(other.nextDH)) {
            return false;
        }
        if (!Arrays.equals(oldMACKeys, other.oldMACKeys)) {
            return false;
        }
        if (recipientKeyID != other.recipientKeyID) {
            return false;
        }
        if (senderKeyID != other.senderKeyID) {
            return false;
        }
        return true;
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        writer.writeByte(this.flags);
        writer.writeInt(this.senderKeyID);
        writer.writeInt(this.recipientKeyID);
        writer.writeDHPublicKey(this.nextDH);
        writer.writeCtr(this.ctr);
        writer.writeData(this.encryptedMessage);
        writer.writeMac(this.mac);
        writer.writeData(this.oldMACKeys);
    }

    @Override
    public int getType() {
        return MESSAGE_DATA;
    }
}
