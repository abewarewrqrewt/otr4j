/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureX;
import net.java.otr4j.profile.ClientProfile;
import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.util.BigIntegers;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.SerializationUtils.ASCII;
import static org.bouncycastle.util.Arrays.concatenate;

// TODO Reconcile two serialization mechanisms (OtrOutputStream and SerializationUtils)
public final class OtrOutputStream implements SerializationConstants, Closeable {

    private final ByteArrayOutputStream out;

    public OtrOutputStream() {
        this.out = new ByteArrayOutputStream();
    }

    public OtrOutputStream(@Nonnull final ByteArrayOutputStream out) {
        this.out = requireNonNull(out);
    }

    @Override
    public void close() {
        try {
            this.out.close();
        } catch (final IOException e) {
            throw new IllegalStateException("ByteArrayOutputStream should never generate an IOException on close.", e);
        }
    }

    @Nonnull
    public byte[] toByteArray() {
        return this.out.toByteArray();
    }

    public void writeBigInt(@Nonnull final BigInteger bi) {
        final byte[] b = BigIntegers.asUnsignedByteArray(bi);
        writeData(b);
    }

    public void writeByte(final int b) {
        writeNumber(b, TYPE_LEN_BYTE);
    }

    public void writeData(@Nullable final byte[] b) {
        final int len = b == null ? 0 : b.length;
        writeNumber(len, DATA_LEN);
        if (len > 0) {
            this.out.write(b, 0, b.length);
        }
    }

    public void writeInt(final int i) {
        writeNumber(i, TYPE_LEN_INT);

    }

    public void writeShort(final int s) {
        writeNumber(s, TYPE_LEN_SHORT);
    }

    // FIXME write unit tests for writeLong.
    public void writeLong(final long value) {
        final byte[] b = new byte[TYPE_LEN_LONG];
        for (int i = 0; i < TYPE_LEN_LONG; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        this.out.write(b, 0, b.length);
    }

    public void writeMac(@Nonnull final byte[] mac) {
        if (mac.length != TYPE_LEN_MAC) {
            throw new IllegalArgumentException();
        }
        this.out.write(mac, 0, mac.length);
    }

    // FIXME investigate if we can make this Nonnull for all cases!
    public void writeCtr(@Nullable final byte[] ctr) {
        if (ctr == null || ctr.length < 1) {
            return;
        }
        int i = 0;
        while (i < TYPE_LEN_CTR && i < ctr.length) {
            this.out.write(ctr[i]);
            i++;
        }
    }

    public void writeDHPublicKey(@Nonnull final DHPublicKey dhPublicKey) {
        final byte[] b = BigIntegers.asUnsignedByteArray(dhPublicKey.getY());
        writeData(b);
    }

    public void writePublicKey(@Nonnull final PublicKey pubKey) {
        if (!(pubKey instanceof DSAPublicKey)) {
            throw new UnsupportedOperationException(
                    "Key types other than DSA are not supported at the moment.");
        }

        final DSAPublicKey dsaKey = (DSAPublicKey) pubKey;

        writeShort(PUBLIC_KEY_TYPE_DSA);

        final DSAParams dsaParams = dsaKey.getParams();
        writeBigInt(dsaParams.getP());
        writeBigInt(dsaParams.getQ());
        writeBigInt(dsaParams.getG());
        writeBigInt(dsaKey.getY());

    }

    public void writeTlvData(@Nullable final byte[] b) {
        final int len = b == null ? 0 : b.length;
        writeNumber(len, TLV_LEN);
        if (len > 0) {
            this.out.write(b, 0, b.length);
        }
    }

    public void writeSignature(@Nonnull final byte[] signature, @Nonnull final PublicKey pubKey) {
        if (!pubKey.getAlgorithm().equals("DSA")) {
            throw new UnsupportedOperationException();
        }
        this.out.write(signature, 0, signature.length);
    }

    public void writeMysteriousX(@Nonnull final SignatureX x) {
        writePublicKey(x.longTermPublicKey);
        writeInt(x.dhKeyID);
        writeSignature(x.signature, x.longTermPublicKey);
    }

    public void writeMysteriousM(@Nonnull final SignatureM m) {
        writeBigInt(m.localPubKey.getY());
        writeBigInt(m.remotePubKey.getY());
        writePublicKey(m.localLongTermPubKey);
        writeInt(m.keyPairID);
    }

    public void writeMysteriousT(@Nonnull final MysteriousT t) {
        writeShort(t.protocolVersion);
        writeByte(t.messageType);
        if (t.protocolVersion == 3) {
            writeInt(t.senderInstanceTag);
            writeInt(t.receiverInstanceTag);
        }
        writeByte(t.flags);
        writeInt(t.senderKeyID);
        writeInt(t.recipientKeyID);
        writeDHPublicKey(t.nextDH);
        writeCtr(t.ctr);
        writeData(t.encryptedMessage);
    }

    public void writePoint(@Nonnull final Point p) {
        writeData(p.encode());
    }

    /**
     * Write Client Profile to stream.
     *
     * @param profile the client profile to serialize.
     */
    // FIXME write unit tests.
    public void writeClientProfile(@Nonnull final ClientProfile profile) {
        writeInt(profile.getIdentifier());
        writeInt(profile.getInstanceTag());
        writePoint(profile.getLongTermPublicKey());
        byte[] versions = new byte[0];
        for (final int version : profile.getVersions()) {
            if (version < 0 || version > 9) {
                throw new IllegalStateException("Negative and multi-digit version numbers are not supported.");
            }
            versions = concatenate(versions, Integer.toString(version).getBytes(ASCII));
        }
        writeData(versions);
        writeLong(profile.getExpirationUnixTime());
        writeData(profile.getTransitionalSignature());
        writeData(profile.getProfileSignature());
        throw new UnsupportedOperationException("TODO implement writing client profile");
    }

    private void writeNumber(final int value, final int length) {
        final byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        this.out.write(b, 0, b.length);
    }
}
