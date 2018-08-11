package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth R Message.
 */
// FIXME write unit tests
public final class AuthRMessage extends AbstractEncodedMessage {

    static final byte MESSAGE_AUTH_R = (byte) 0x91;

    private final ClientProfilePayload clientProfile;

    private final Point x;

    private final BigInteger a;

    private final OtrCryptoEngine4.Sigma sigma;

    /**
     * Auth-R Message as used in OTRv4.
     *
     * @param protocolVersion   the protocol version
     * @param senderInstance    the sender instance tag
     * @param recipientInstance the receiver instance tag
     * @param clientProfile     the client profile (as payload)
     * @param x                 the ECDH public key 'X'
     * @param a                 the DH public key 'A'
     * @param sigma             the ring signature
     */
    public AuthRMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                        @Nonnull final ClientProfilePayload clientProfile, @Nonnull final Point x, @Nonnull final BigInteger a,
                        @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(Session.OTRv.FOUR, protocolVersion), senderInstance, recipientInstance);
        this.clientProfile = requireNonNull(clientProfile);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_R;
    }

    /**
     * Get the client profile payload.
     *
     * @return Returns the client profile payload.
     */
    @Nonnull
    public ClientProfilePayload getClientProfile() {
        return clientProfile;
    }

    /**
     * Get ECDH public key 'X'.
     *
     * @return Returns the public key 'X'.
     */
    @Nonnull
    public Point getX() {
        return x;
    }

    /**
     * Get DH public key 'A'.
     *
     * @return Returns the public key 'A'.
     */
    @Nonnull
    public BigInteger getA() {
        return a;
    }

    /**
     * Get the ring signature.
     *
     * @return Returns the ring signature.
     */
    @Nonnull
    public OtrCryptoEngine4.Sigma getSigma() {
        return sigma;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(this.clientProfile);
        writer.writePoint(this.x);
        writer.writeBigInt(this.a);
        writer.write(this.sigma);
    }
}
