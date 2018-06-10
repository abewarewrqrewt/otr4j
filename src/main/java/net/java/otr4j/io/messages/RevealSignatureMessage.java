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

/**
 * OTRv2 AKE Reveal Signature message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// FIXME add exact protocol version checks for OTRv2/OTRv3 message types.
public final class RevealSignatureMessage extends AbstractEncodedMessage {

    static final int MESSAGE_REVEALSIG = 0x11;

    public final byte[] revealedKey;
    public final byte[] xEncrypted;
    public final byte[] xEncryptedMAC;

    public RevealSignatureMessage(final int protocolVersion,
            @Nonnull final byte[] xEncrypted,
            @Nonnull final byte[] xEncryptedMAC,
            @Nonnull final byte[] revealedKey,
            final int senderInstance,
            final int receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        this.xEncrypted = Objects.requireNonNull(xEncrypted);
        this.xEncryptedMAC = Objects.requireNonNull(xEncryptedMAC);
        this.revealedKey = Objects.requireNonNull(revealedKey);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(revealedKey);
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
        RevealSignatureMessage other = (RevealSignatureMessage) obj;
        if (!Arrays.equals(revealedKey, other.revealedKey)) {
            return false;
        }
        return true;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeData(this.revealedKey);
        writer.writeData(this.xEncrypted);
        writer.writeMac(this.xEncryptedMAC);
    }

    @Override
    public int getType() {
        return MESSAGE_REVEALSIG;
    }
}
