/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.util.Arrays;

import static net.java.otr4j.io.messages.DataMessage.MESSAGE_DATA;

/**
 * MysteriousT represents the T_a composite as described in "Exchanging Data" section.
 */
// TODO Check if we can merge MysteriousT and DataMessage. MysteriousT is described in the "Exchanging Data" section as T_a. It's basically a DataMessage except without MAC as it still has to be calculated from serialized MysteriousT content.
public final class MysteriousT {

    // Fields.
    public final int protocolVersion;
    public final int senderInstanceTag;
    public final int receiverInstanceTag;
    public final int messageType;
    public final int flags;
    public final int senderKeyID;
    public final int recipientKeyID;
    public final DHPublicKey nextDH;
    public final byte[] ctr;
    public final byte[] encryptedMessage;

    // Ctor.
    public MysteriousT(final int protocolVersion, final int senderInstanceTag, final int receiverInstanceTag,
                       final int flags, final int senderKeyID, final int recipientKeyID,
                       @Nonnull final DHPublicKey nextDH, @Nonnull final byte[] ctr,
                       @Nonnull final byte[] encryptedMessage) {

        this.protocolVersion = protocolVersion;
        this.senderInstanceTag = senderInstanceTag;
        this.receiverInstanceTag = receiverInstanceTag;
        this.messageType = MESSAGE_DATA;
        this.flags = flags;
        this.senderKeyID = senderKeyID;
        this.recipientKeyID = recipientKeyID;
        this.nextDH = nextDH;
        this.ctr = ctr;
        this.encryptedMessage = encryptedMessage;
    }

    // Methods.
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(ctr);
        result = prime * result + Arrays.hashCode(encryptedMessage);
        result = prime * result + flags;
        result = prime * result + messageType;
        result = prime * result + nextDH.hashCode();
        result = prime * result + protocolVersion;
        result = prime * result + recipientKeyID;
        result = prime * result + senderKeyID;
        result = prime * result + senderInstanceTag;
        result = prime * result + receiverInstanceTag;
        return result;
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
        MysteriousT other = (MysteriousT) obj;
        if (!Arrays.equals(ctr, other.ctr)) {
            return false;
        }
        if (!Arrays.equals(encryptedMessage, other.encryptedMessage)) {
            return false;
        }
        if (flags != other.flags) {
            return false;
        }
        if (messageType != other.messageType) {
            return false;
        }
        if (!nextDH.equals(other.nextDH)) {
            return false;
        }
        if (protocolVersion != other.protocolVersion) {
            return false;
        }
        if (recipientKeyID != other.recipientKeyID) {
            return false;
        }
        if (senderKeyID != other.senderKeyID) {
            return false;
        }
        if (senderInstanceTag != other.senderInstanceTag) {
            return false;
        }
        return receiverInstanceTag == other.receiverInstanceTag;
    }

}
