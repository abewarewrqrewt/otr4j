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
 * OTRv2 AKE Signature message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// FIXME add exact protocol version checks for OTRv2/OTRv3 message types.
public final class SignatureMessage extends AbstractEncodedMessage {

    static final int MESSAGE_SIGNATURE = 0x12;

    public final byte[] xEncrypted;
    public final byte[] xEncryptedMAC;

    public SignatureMessage(final int protocolVersion,
            @Nonnull final byte[] xEncrypted,
            @Nonnull final byte[] xEncryptedMAC,
            final int senderInstance,
            final int receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        this.xEncrypted = Objects.requireNonNull(xEncrypted);
        this.xEncryptedMAC = Objects.requireNonNull(xEncryptedMAC);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(xEncrypted);
        result = prime * result + Arrays.hashCode(xEncryptedMAC);
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
        SignatureMessage other = (SignatureMessage) obj;
        if (!Arrays.equals(xEncrypted, other.xEncrypted)) {
            return false;
        }
        if (!Arrays.equals(xEncryptedMAC, other.xEncryptedMAC)) {
            return false;
        }
        return true;
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) {
        super.write(writer);
        writer.writeData(this.xEncrypted);
        writer.writeMac(this.xEncryptedMAC);
    }

    @Override
    public int getType() {
        return MESSAGE_SIGNATURE;
    }
}
