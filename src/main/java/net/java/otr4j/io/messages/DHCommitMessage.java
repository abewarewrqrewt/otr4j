/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Objects;

import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * OTRv2 AKE DH-Commit message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// FIXME add exact protocol version checks for OTRv2/OTRv3 message types.
public final class DHCommitMessage extends AbstractEncodedMessage {

    static final int MESSAGE_DH_COMMIT = 0x02;

    public final byte[] dhPublicKeyEncrypted;
    public final byte[] dhPublicKeyHash;

    public DHCommitMessage(final int protocolVersion,
            @Nonnull final byte[] dhPublicKeyHash,
            @Nonnull final byte[] dhPublicKeyEncrypted,
            final int senderInstance,
            final int receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        this.dhPublicKeyEncrypted = Objects.requireNonNull(dhPublicKeyEncrypted);
        this.dhPublicKeyHash = Objects.requireNonNull(dhPublicKeyHash);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(dhPublicKeyEncrypted);
        result = prime * result + Arrays.hashCode(dhPublicKeyHash);
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
        final DHCommitMessage other = (DHCommitMessage) obj;
        if (!constantTimeEquals(dhPublicKeyEncrypted, other.dhPublicKeyEncrypted)) {
            return false;
        }
        if (!constantTimeEquals(dhPublicKeyHash, other.dhPublicKeyHash)) {
            return false;
        }
        return true;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeData(this.dhPublicKeyEncrypted);
        writer.writeData(this.dhPublicKeyHash);
    }

    @Override
    public int getType() {
        return MESSAGE_DH_COMMIT;
    }
}
