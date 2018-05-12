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
import net.java.otr4j.profile.UserProfile;
import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.util.BigIntegers;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.SerializationUtils.UTF8;
import static org.bouncycastle.util.Arrays.concatenate;

// TODO Reconcile two serialization mechanisms (OtrOutputStream and SerializationUtils)
public final class OtrOutputStream extends FilterOutputStream implements
        SerializationConstants {

    public OtrOutputStream(@Nonnull final OutputStream out) {
        super(requireNonNull(out));
    }

    private void writeNumber(final int value, final int length) throws IOException {
        final byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        write(b);
    }

    public void writeBigInt(@Nonnull final BigInteger bi) throws IOException {
        final byte[] b = BigIntegers.asUnsignedByteArray(bi);
        writeData(b);
    }

    public void writeByte(final int b) throws IOException {
        writeNumber(b, TYPE_LEN_BYTE);
    }

    public void writeData(@Nullable final byte[] b) throws IOException {
        final int len = b == null ? 0 : b.length;
        writeNumber(len, DATA_LEN);
        if (len > 0) {
            write(b);
        }
    }

    public void writeInt(final int i) throws IOException {
        writeNumber(i, TYPE_LEN_INT);

    }

    public void writeShort(final int s) throws IOException {
        writeNumber(s, TYPE_LEN_SHORT);

    }

    // FIXME write unit tests for writeLong.
    public void writeLong(final long value) throws IOException {
        final byte[] b = new byte[TYPE_LEN_LONG];
        for (int i = 0; i < TYPE_LEN_LONG; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        write(b);
    }

    public void writeMac(@Nonnull final byte[] mac) throws IOException {
        if (mac.length != TYPE_LEN_MAC) {
            throw new IllegalArgumentException();
        }

        write(mac);
    }

    public void writeCtr(@Nullable final byte[] ctr) throws IOException {
        if (ctr == null || ctr.length < 1) {
            return;
        }

        int i = 0;
        while (i < TYPE_LEN_CTR && i < ctr.length) {
            write(ctr[i]);
            i++;
        }
    }

    public void writeDHPublicKey(@Nonnull final DHPublicKey dhPublicKey) throws IOException {
        final byte[] b = BigIntegers.asUnsignedByteArray(dhPublicKey.getY());
        writeData(b);
    }

    public void writePublicKey(@Nonnull final PublicKey pubKey) throws IOException {
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

    public void writeTlvData(@Nullable final byte[] b) throws IOException {
        final int len = b == null ? 0 : b.length;
        writeNumber(len, TLV_LEN);
        if (len > 0) {
            write(b);
        }
    }

    public void writeSignature(@Nonnull final byte[] signature, @Nonnull final PublicKey pubKey)
            throws IOException {
        if (!pubKey.getAlgorithm().equals("DSA")) {
            throw new UnsupportedOperationException();
        }
        out.write(signature);
    }

    public void writeMysteriousX(@Nonnull final SignatureX x) throws IOException {
        writePublicKey(x.longTermPublicKey);
        writeInt(x.dhKeyID);
        writeSignature(x.signature, x.longTermPublicKey);
    }

    public void writeMysteriousX(@Nonnull final SignatureM m) throws IOException {
        writeBigInt(m.localPubKey.getY());
        writeBigInt(m.remotePubKey.getY());
        writePublicKey(m.localLongTermPubKey);
        writeInt(m.keyPairID);
    }

    public void writeMysteriousT(@Nonnull final MysteriousT t) throws IOException {
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

    public void writePoint(@Nonnull final Point p) throws IOException {
        writeData(p.encode());
    }

    /**
     * Write User Profile to stream.
     *
     * @param profile the user profile to serialize.
     * @throws IOException Thrown in case of failure to serialize a part of the user profile.
     */
    // FIXME write unit tests.
    public void writeUserProfile(@Nonnull final UserProfile profile) throws IOException {
        writeInt(profile.getIdentifier());
        writeInt(profile.getInstanceTag());
        writePoint(profile.getLongTermPublicKey());
        byte[] versions = new byte[0];
        for (final int version : profile.getVersions()) {
            if (version < 0 || version > 9) {
                throw new IllegalStateException("Negative and double-digit version numbers are not supported.");
            }
            versions = concatenate(versions, Integer.toString(version).getBytes(UTF8));
        }
        writeData(versions);
        writeLong(profile.getExpirationUnixTime());
        writeData(profile.getTransitionalSignature());
        writeData(profile.getProfileSignature());
        throw new UnsupportedOperationException("TODO implement writing user profile");
    }
}
