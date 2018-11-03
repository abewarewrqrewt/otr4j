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
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * The OTRv4 data message.
 */
// TODO two constants defined in duplicate, due to value needed in multiple packages: XSALSA20_IV_LENGTH_BYTES, MAC_LENGTH_BYTES
@SuppressWarnings("PMD.MethodReturnsInternalArray")
public final class DataMessage4 extends AbstractEncodedMessage {

    static final int MESSAGE_DATA = 0x03;

    private static final int XSALSA20_IV_LENGTH_BYTES = 24;
    private static final int MAC_LENGTH_BYTES = 64;

    private final byte flags;
    private final int pn;
    private final int i;
    private final int j;
    private final Point ecdhPublicKey;
    private final BigInteger dhPublicKey;
    private final byte[] nonce;
    private final byte[] ciphertext;
    private final byte[] authenticator;
    private final byte[] revealedMacs;

    /**
     * Constructor for the data message.
     *
     * @param protocolVersion     the protocol version
     * @param senderInstanceTag   the sender instance tag
     * @param receiverInstanceTag the receiver instance tag
     * @param flags               the message flags
     * @param pn                  the number of messages in previous ratchet
     * @param i                   the ratchet ID
     * @param j                   the message ID
     * @param ecdhPublicKey       the ECDH public key
     * @param dhPublicKey         the DH public key (is only present every third ratchet)
     * @param nonce               the nonce
     * @param ciphertext          the ciphertext
     * @param authenticator       the authenticator code
     * @param revealedMacs        the revealed MAC keys
     */
    public DataMessage4(final int protocolVersion, @Nonnull final InstanceTag senderInstanceTag,
            @Nonnull final InstanceTag receiverInstanceTag, final byte flags, final int pn, final int i, final int j,
            @Nonnull final Point ecdhPublicKey, @Nullable final BigInteger dhPublicKey, @Nonnull final byte[] nonce,
            @Nonnull final byte[] ciphertext, @Nonnull final byte[] authenticator, @Nonnull final byte[] revealedMacs) {
        super(requireInRange(OTRv.FOUR, OTRv.FOUR, protocolVersion), senderInstanceTag, receiverInstanceTag);
        this.flags = flags;
        this.pn = pn;
        this.i = i;
        this.j = j;
        this.ecdhPublicKey = requireNonNull(ecdhPublicKey);
        this.dhPublicKey = dhPublicKey;
        this.nonce = requireLengthExactly(XSALSA20_IV_LENGTH_BYTES, nonce);
        this.ciphertext = requireNonNull(ciphertext);
        this.authenticator = requireLengthExactly(MAC_LENGTH_BYTES, authenticator);
        this.revealedMacs = requireNonNull(revealedMacs);
    }

    @Override
    public int getType() {
        return MESSAGE_DATA;
    }

    /**
     * Get message flags.
     *
     * @return Returns flags value.
     */
    public byte getFlags() {
        return flags;
    }

    /**
     * Get number of messages in previous ratchet.
     *
     * @return Returns the number.
     */
    public int getPn() {
        return pn;
    }

    /**
     * Get ratchet ID.
     *
     * @return Returns the ID.
     */
    public int getI() {
        return i;
    }

    /**
     * Get the message ID.
     *
     * @return Returns the ID.
     */
    public int getJ() {
        return j;
    }

    /**
     * Get the ECDH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getEcdhPublicKey() {
        return ecdhPublicKey;
    }

    /**
     * Get the DH public key.
     *
     * @return Returns the public key.
     */
    @Nullable
    public BigInteger getDhPublicKey() {
        return dhPublicKey;
    }

    /**
     * Get the nonce used in the data message.
     *
     * @return Returns the nonce.
     */
    @Nonnull
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Get the ciphertext contained in the data message.
     *
     * @return Returns the ciphertext.
     */
    @Nonnull
    public byte[] getCiphertext() {
        return ciphertext;
    }

    /**
     * Get the authenticator.
     *
     * @return Returns the authenticator.
     */
    @Nonnull
    public byte[] getAuthenticator() {
        return authenticator;
    }

    /**
     * Get the revealed MAC codes as a byte-array.
     *
     * @return Returns the MAC codes.
     */
    @Nonnull
    public byte[] getRevealedMacs() {
        return revealedMacs;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        final DataMessage4 that = (DataMessage4) o;
        return flags == that.flags && pn == that.pn && i == that.i && j == that.j
                && Objects.equals(ecdhPublicKey, that.ecdhPublicKey) && Objects.equals(dhPublicKey, that.dhPublicKey)
                && constantTimeEquals(nonce, that.nonce) && constantTimeEquals(ciphertext, that.ciphertext)
                && constantTimeEquals(authenticator, that.authenticator)
                // Note: revealed MACs are not sensitive, so there is no sense in comparing constant-time
                && Arrays.equals(revealedMacs, that.revealedMacs);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), flags, pn, i, j, ecdhPublicKey, dhPublicKey);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(authenticator);
        result = 31 * result + Arrays.hashCode(revealedMacs);
        return result;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        writeDataMessageSections(writer);
        writer.writeMacOTR4(this.authenticator);
        writer.writeData(this.revealedMacs);
    }

    /**
     * Write the first part of the Data message.
     *
     * @param writer the output stream to write to.
     */
    public void writeDataMessageSections(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeByte(this.flags);
        writer.writeInt(this.pn);
        writer.writeInt(this.i);
        writer.writeInt(this.j);
        writer.writePoint(this.ecdhPublicKey);
        if (this.dhPublicKey == null) {
            writer.writeData(new byte[0]);
        } else {
            writer.writeBigInt(this.dhPublicKey);
        }
        writer.writeNonce(this.nonce);
        writer.writeData(this.ciphertext);
    }
}
