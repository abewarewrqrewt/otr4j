package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

public final class DataMessage4 extends AbstractEncodedMessage {

    // TODO consider if we want to use this or transform to an enum.
    private static final byte FLAG_IGNORE_UNREADABLE = 0x1;

    static final int MESSAGE_DATA = 0x03;

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

    public DataMessage4(final int protocolVersion, final int senderInstanceTag, final int receiverInstanceTag,
                        final byte flags, final int pn, final int i, final int j, @Nonnull final Point ecdhPublicKey,
                        @Nonnull final BigInteger dhPublicKey, @Nonnull final byte[] nonce,
                        @Nonnull final byte[] ciphertext, @Nonnull final byte[] authenticator,
                        @Nonnull final byte[] revealedMacs) {
        super(protocolVersion, senderInstanceTag, receiverInstanceTag);
        this.flags = flags;
        this.pn = pn;
        this.i = i;
        this.j = j;
        this.ecdhPublicKey = requireNonNull(ecdhPublicKey);
        this.dhPublicKey = requireNonNull(dhPublicKey);
        // FIXME replace literal with constant of XSALSA20_IV_LENGTH_BYTES.
        this.nonce = requireLengthExactly(24, nonce);
        this.ciphertext = requireNonNull(ciphertext);
        // FIXME replace literal with constant of OTRv4 MAC length.
        this.authenticator = requireLengthExactly(64, authenticator);
        this.revealedMacs = requireNonNull(revealedMacs);
    }

    @Override
    public int getType() {
        return MESSAGE_DATA;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeByte(this.flags);
        writer.writeInt(this.pn);
        writer.writeInt(this.i);
        writer.writeInt(this.j);
        writer.writePoint(this.ecdhPublicKey);
        writer.writeBigInt(this.dhPublicKey);
        writer.writeNonce(this.nonce);
        writer.writeData(this.ciphertext);
        writer.writeMacOTR4(this.authenticator);
        writer.writeData(this.revealedMacs);
    }
}
