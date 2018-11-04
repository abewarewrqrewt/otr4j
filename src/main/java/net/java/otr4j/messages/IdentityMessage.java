/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * OTRv4 Interactive DAKE Identity Message.
 *
 * The identity message is used to send initial identity information upon establishing a new session.
 */
public final class IdentityMessage extends AbstractEncodedMessage {

    // OTRv4 Encoded message types
    static final int MESSAGE_IDENTITY = 0x35;

    private final ClientProfilePayload clientProfile;
    private final Point y;
    private final BigInteger b;

    /**
     * Identity message type of OTRv4.
     *
     * @param protocolVersion  the protocol version
     * @param senderInstance   the sender instance tag
     * @param receiverInstance the receiver instance tag
     * @param clientProfile    the client profile (as payload)
     * @param y                the ECDH public key 'Y'
     * @param b                the DH public key 'B'
     */
    public IdentityMessage(final int protocolVersion, @Nonnull final InstanceTag senderInstance,
            @Nonnull final InstanceTag receiverInstance, @Nonnull final ClientProfilePayload clientProfile,
            @Nonnull final Point y, @Nonnull final BigInteger b) {
        super(requireInRange(OTRv.FOUR, OTRv.FOUR, protocolVersion), senderInstance, receiverInstance);
        this.clientProfile = requireNonNull(clientProfile);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
    }

    @Override
    public int getType() {
        return MESSAGE_IDENTITY;
    }

    /**
     * Get client profile (as payload).
     *
     * @return Returns the client profile payload.
     */
    @Nonnull
    public ClientProfilePayload getClientProfile() {
        return clientProfile;
    }

    /**
     * Get ECDH public key 'Y'.
     *
     * @return Returns ECDH public key 'Y'.
     */
    @Nonnull
    public Point getY() {
        return y;
    }

    /**
     * Get DH public key 'B'.
     *
     * @return Returns DH public key 'B'.
     */
    @Nonnull
    public BigInteger getB() {
        return b;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(clientProfile);
        writer.writePoint(this.y);
        writer.writeBigInt(this.b);
    }
}
