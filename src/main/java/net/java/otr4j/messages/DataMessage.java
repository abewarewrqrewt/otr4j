/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * OTRv2/3 encrypted data message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class DataMessage extends AbstractEncodedMessage {

    static final int MESSAGE_DATA = 0x03;

    /**
     * Flags.
     */
    public final byte flags;
    /**
     * Sender key ID.
     */
    public final int senderKeyID;
    /**
     * Receiver key ID.
     */
    public final int recipientKeyID;
    /**
     * Next DH public key.
     */
    @Nonnull
    public final DHPublicKey nextDH;
    /**
     * Counter value used while encrypting this Data message.
     */
    @Nonnull
    public final byte[] ctr;
    /**
     * The encrypted message content.
     */
    @Nonnull
    public final byte[] encryptedMessage;
    /**
     * The MAC for the message content.
     */
    @Nonnull
    public final byte[] mac;
    /**
     * Old MAC keys (to be) revealed.
     */
    @Nonnull
    public final byte[] oldMACKeys;

    /**
     * Construct Data message.
     *
     * @param t                   mysterious T value
     * @param mac                 the MAC
     * @param oldMACKeys          old MAC keys to be revealed
     * @param senderInstanceTag   the sender instance tag
     * @param receiverInstanceTag the receiver instance tag
     */
    public DataMessage(@Nonnull final MysteriousT t, @Nonnull final byte[] mac, @Nonnull final byte[] oldMACKeys,
            @Nonnull final InstanceTag senderInstanceTag, @Nonnull final InstanceTag receiverInstanceTag) {
        this(t.protocolVersion, t.flags, t.senderKeyID, t.recipientKeyID, t.nextDH, t.ctr, t.encryptedMessage, mac,
                oldMACKeys, senderInstanceTag, receiverInstanceTag);
    }

    /**
     * Constructor for Data message.
     *
     * @param protocolVersion     the protocol version
     * @param flags               the Data message flags
     * @param senderKeyID         the sender key ID
     * @param recipientKeyID      the receiver key ID
     * @param nextDH              the Next DH public key to be rotated to
     * @param ctr                 the counter value used in this Data message
     * @param encryptedMessage    the encrypted message content
     * @param mac                 the MAC for the message content
     * @param oldMACKeys          the old MAC keys to reveal
     * @param senderInstanceTag   the sender instance tag
     * @param receiverInstanceTag the receiver instance tag
     */
    public DataMessage(final int protocolVersion, final byte flags, final int senderKeyID,
            final int recipientKeyID, @Nonnull final DHPublicKey nextDH,
            @Nonnull final byte[] ctr, @Nonnull final byte[] encryptedMessage,
            @Nonnull final byte[] mac, @Nonnull final byte[] oldMACKeys,
            @Nonnull final InstanceTag senderInstanceTag, @Nonnull final InstanceTag receiverInstanceTag) {
        super(protocolVersion, senderInstanceTag, receiverInstanceTag);
        this.flags = flags;
        this.senderKeyID = senderKeyID;
        this.recipientKeyID = recipientKeyID;
        this.nextDH = requireNonNull(nextDH);
        this.ctr = requireNonNull(ctr);
        this.encryptedMessage = requireNonNull(encryptedMessage);
        this.mac = requireNonNull(mac);
        this.oldMACKeys = requireNonNull(oldMACKeys);
    }

    /**
     * Get mysterious 'T' value.
     *
     * @return Returns 'T'.
     */
    public MysteriousT getT() {
        return new MysteriousT(protocolVersion, senderTag,
                receiverTag, flags, senderKeyID,
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
        result = prime * result + nextDH.hashCode();
        result = prime * result + Arrays.hashCode(oldMACKeys);
        result = prime * result + recipientKeyID;
        result = prime * result + senderKeyID;
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DataMessage other = (DataMessage) obj;
        if (!constantTimeEquals(ctr, other.ctr)) {
            return false;
        }
        if (!constantTimeEquals(encryptedMessage, other.encryptedMessage)) {
            return false;
        }
        if (flags != other.flags) {
            return false;
        }
        if (!constantTimeEquals(mac, other.mac)) {
            return false;
        }
        if (!nextDH.equals(other.nextDH)) {
            return false;
        }
        if (!constantTimeEquals(oldMACKeys, other.oldMACKeys)) {
            return false;
        }
        if (recipientKeyID != other.recipientKeyID) {
            return false;
        }
        return senderKeyID == other.senderKeyID;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
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
