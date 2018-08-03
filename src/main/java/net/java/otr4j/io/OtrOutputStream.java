/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.EncodingConstants.DATA_LEN;
import static net.java.otr4j.io.EncodingConstants.EDDSA_SIGNATURE_LENGTH_BYTES;
import static net.java.otr4j.io.EncodingConstants.PUBLIC_KEY_TYPE_DSA;
import static net.java.otr4j.io.EncodingConstants.TLV_LEN;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_BYTE;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_CTR;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_INT;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_LONG;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_MAC;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_MAC_OTR4;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_NONCE;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_SHORT;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

// TODO consider adding write-method for Iterable<OtrEncodable>
public final class OtrOutputStream {

    private final ByteArrayOutputStream out;

    public OtrOutputStream() {
        this.out = new ByteArrayOutputStream();
    }

    public OtrOutputStream(@Nonnull final ByteArrayOutputStream out) {
        this.out = requireNonNull(out);
    }

    @Nonnull
    public byte[] toByteArray() {
        return this.out.toByteArray();
    }

    public OtrOutputStream write(@Nonnull final OtrEncodable encodable) {
        encodable.writeTo(this);
        return this;
    }

    public OtrOutputStream writeBigInt(@Nonnull final BigInteger bi) {
        writeData(asUnsignedByteArray(bi));
        return this;
    }

    public OtrOutputStream writeByte(final int b) {
        writeNumber(b, TYPE_LEN_BYTE);
        return this;
    }

    public OtrOutputStream writeData(@Nonnull final byte[] b) {
        writeNumber(b.length, DATA_LEN);
        if (b.length > 0) {
            this.out.write(b, 0, b.length);
        }
        return this;
    }

    public OtrOutputStream writeInt(final int i) {
        writeNumber(i, TYPE_LEN_INT);
        return this;
    }

    public OtrOutputStream writeShort(final int s) {
        writeNumber(s, TYPE_LEN_SHORT);
        return this;
    }

    public OtrOutputStream writeLong(final long value) {
        final byte[] b = new byte[TYPE_LEN_LONG];
        for (int i = 0; i < TYPE_LEN_LONG; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        this.out.write(b, 0, b.length);
        return this;
    }

    public OtrOutputStream writeMac(@Nonnull final byte[] mac) {
        requireLengthExactly(TYPE_LEN_MAC, mac);
        this.out.write(mac, 0, mac.length);
        return this;
    }

    public OtrOutputStream writeCtr(@Nonnull final byte[] ctr) {
        if (ctr.length < 1) {
            return this;
        }
        int i = 0;
        while (i < TYPE_LEN_CTR && i < ctr.length) {
            this.out.write(ctr[i]);
            i++;
        }
        return this;
    }

    public OtrOutputStream writeDHPublicKey(@Nonnull final DHPublicKey dhPublicKey) {
        writeData(asUnsignedByteArray(dhPublicKey.getY()));
        return this;
    }

    public OtrOutputStream writePublicKey(@Nonnull final DSAPublicKey pubKey) {
        writeShort(PUBLIC_KEY_TYPE_DSA);
        final DSAParams dsaParams = pubKey.getParams();
        writeBigInt(dsaParams.getP());
        writeBigInt(dsaParams.getQ());
        writeBigInt(dsaParams.getG());
        writeBigInt(pubKey.getY());
        return this;
    }

    public OtrOutputStream writeTlvData(@Nullable final byte[] b) {
        final int len = b == null ? 0 : b.length;
        writeNumber(len, TLV_LEN);
        if (len > 0) {
            this.out.write(b, 0, b.length);
        }
        return this;
    }

    // TODO why pass on public key if you're not going to use it? Seems senseless. Simplify.
    public OtrOutputStream writeSignature(@Nonnull final byte[] signature, @Nonnull final PublicKey pubKey) {
        if (!pubKey.getAlgorithm().equals("DSA")) {
            throw new UnsupportedOperationException();
        }
        this.out.write(signature, 0, signature.length);
        return this;
    }

    /**
     * Write an XSalsa20 nonce.
     *
     * @param nonce The nonce.
     */
    // FIXME add unit tests.
    public OtrOutputStream writeNonce(@Nonnull final byte[] nonce) {
        requireLengthExactly(TYPE_LEN_NONCE, nonce);
        this.out.write(nonce, 0, nonce.length);
        return this;
    }

    /**
     * Write an OTRv4 MAC.
     *
     * @param mac 64-byte MAC as used in OTRv4
     */
    // FIXME add unit tests.
    public OtrOutputStream writeMacOTR4(@Nonnull final byte[] mac) {
        requireLengthExactly(TYPE_LEN_MAC_OTR4, mac);
        this.out.write(mac, 0, mac.length);
        return this;
    }

    /**
     * Write an Edwards point encoded according to RFC8032.
     *
     * @param p The Edwards point.
     */
    // FIXME add unit tests.
    public OtrOutputStream writePoint(@Nonnull final Point p) {
        writeData(p.encode());
        return this;
    }

    /**
     * Write an EdDSA signature.
     *
     * @param signature A signature consisting of exactly 114 bytes is expected.
     */
    // FIXME add unit tests.
    public OtrOutputStream writeEdDSASignature(@Nonnull final byte[] signature) {
        requireLengthExactly(EDDSA_SIGNATURE_LENGTH_BYTES, signature);
        this.out.write(signature, 0, signature.length);
        return this;
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
