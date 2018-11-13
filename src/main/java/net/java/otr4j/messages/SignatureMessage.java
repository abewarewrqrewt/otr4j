/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * OTRv2 AKE Signature message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class SignatureMessage extends AbstractEncodedMessage {

    static final int MESSAGE_SIGNATURE = 0x12;

    /**
     * Encrypted X.
     */
    public final byte[] xEncrypted;
    /**
     * MAC of encrypted X.
     */
    public final byte[] xEncryptedMAC;

    /**
     * Constructor.
     *
     * @param protocolVersion  the protocol version
     * @param xEncrypted       encrypted X
     * @param xEncryptedMAC    MAC of encrypted X
     * @param senderInstance   sender instance tag
     * @param receiverInstance receiver instance tag
     */
    public SignatureMessage(final int protocolVersion, @Nonnull final byte[] xEncrypted,
            @Nonnull final byte[] xEncryptedMAC, @Nonnull final InstanceTag senderInstance,
            @Nonnull final InstanceTag receiverInstance) {
        super(requireInRange(Version.TWO, Version.THREE, protocolVersion), senderInstance, receiverInstance);
        this.xEncrypted = requireNonNull(xEncrypted);
        this.xEncryptedMAC = requireNonNull(xEncryptedMAC);
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
        final SignatureMessage other = (SignatureMessage) obj;
        if (!constantTimeEquals(xEncrypted, other.xEncrypted)) {
            return false;
        }
        return constantTimeEquals(xEncryptedMAC, other.xEncryptedMAC);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeData(this.xEncrypted);
        writer.writeMac(this.xEncryptedMAC);
    }

    @Override
    public int getType() {
        return MESSAGE_SIGNATURE;
    }
}
