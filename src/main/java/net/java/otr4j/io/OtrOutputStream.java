/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.TLV;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
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

/**
 * Output stream for OTR encoding.
 */
// TODO consider adding write-method for Iterable<OtrEncodable>
public final class OtrOutputStream {

    private static final int ZERO_LENGTH = 0;

    private final ByteArrayOutputStream out;

    /**
     * Constructor for OTR-encoded output stream.
     */
    public OtrOutputStream() {
        this.out = new ByteArrayOutputStream();
    }

    /**
     * Constructor for OTR-encoded output stream based on injected ByteArrayOutputStream.
     *
     * @param out the byte-array output stream
     */
    public OtrOutputStream(@Nonnull final ByteArrayOutputStream out) {
        this.out = requireNonNull(out);
    }

    /**
     * Produce byte-array resulting from output stream use.
     *
     * @return Returns the byte-array.
     */
    @Nonnull
    public byte[] toByteArray() {
        return this.out.toByteArray();
    }

    /**
     * Write the OTR-encodable to the output stream.
     *
     * @param encodable the encodable entity
     * @return Returns the output stream such that chaining method calls is possible.
     */
    @Nonnull
    public OtrOutputStream write(@Nonnull final OtrEncodable encodable) {
        encodable.writeTo(this);
        return this;
    }

    /**
     * Write a plaintext message in OTR-encoded format.
     * <p>
     * Convert the {@code String} text to a {@code byte[]}, including sanitizing
     * it to make sure no corrupt characters conflict with bytes that have
     * special meaning in OTR. Mostly, this means removing NULL bytes, since
     * {@code 0x00} is used as the separator between the message and the TLVs
     * in an OTR Data Message.
     *
     * @param message the plain text message being sent
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeMessage(@Nonnull final String message) {
        if (message.isEmpty()) {
            return this;
        }
        final byte[] messageBytes = message.replace('\0', '?').getBytes(UTF_8);
        this.out.write(messageBytes, 0, messageBytes.length);
        return this;
    }

    /**
     * Write TLV in OTR-encoded format.
     * <p>
     * NOTE: this method does not prefix the '\0' byte between message and TLV records. This byte has to be prefixed
     * manually.
     *
     * @param tlvs TLV records
     * @return Returns OtrOutputStream instance such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeTLV(@Nonnull final Iterable<TLV> tlvs) {
        for (final TLV tlv : tlvs) {
            this.writeShort(tlv.getType()).writeTlvData(tlv.getValue());
        }
        return this;
    }

    @Nonnull
    private OtrOutputStream writeTlvData(@Nonnull final byte[] b) {
        writeNumber(b.length, TLV_LEN);
        if (b.length > 0) {
            this.out.write(b, 0, b.length);
        }
        return this;
    }

    /**
     * Write Big Integer (MPI) value to output stream.
     *
     * @param bi big integer value
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeBigInt(@Nonnull final BigInteger bi) {
        writeData(asUnsignedByteArray(bi));
        return this;
    }

    /**
     * Write a byte to the output stream.
     *
     * @param b the byte b
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeByte(final int b) {
        writeNumber(b, TYPE_LEN_BYTE);
        return this;
    }

    /**
     * Write byte-array in variable-length data representation to the output stream.
     *
     * @param b the byte-array b
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeData(@Nonnull final byte[] b) {
        writeNumber(b.length, DATA_LEN);
        if (b.length > 0) {
            this.out.write(b, 0, b.length);
        }
        return this;
    }

    /**
     * Write an integer (4-byte) value to the output stream.
     *
     * @param i the integer value
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeInt(final int i) {
        writeNumber(i, TYPE_LEN_INT);
        return this;
    }

    /**
     * Write a short (2-byte) value to the output stream.
     *
     * @param s the short value
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeShort(final int s) {
        writeNumber(s, TYPE_LEN_SHORT);
        return this;
    }

    /**
     * Write a long (8-byte) value to the output stream.
     *
     * @param value the long value
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeLong(final long value) {
        final byte[] b = new byte[TYPE_LEN_LONG];
        for (int i = 0; i < TYPE_LEN_LONG; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        this.out.write(b, 0, b.length);
        return this;
    }

    /**
     * Write OTRv3 MAC value to the output stream.
     *
     * @param mac the MAC
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeMac(@Nonnull final byte[] mac) {
        requireLengthExactly(TYPE_LEN_MAC, mac);
        this.out.write(mac, 0, mac.length);
        return this;
    }

    /**
     * Write OTRv3 counter value to the output stream.
     *
     * @param ctr the counter value
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeCtr(@Nonnull final byte[] ctr) {
        if (ctr.length <= ZERO_LENGTH) {
            return this;
        }
        int i = 0;
        while (i < TYPE_LEN_CTR && i < ctr.length) {
            this.out.write(ctr[i]);
            i++;
        }
        return this;
    }

    /**
     * Write DH public key value to output stream.
     *
     * @param dhPublicKey the DH public key
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeDHPublicKey(@Nonnull final DHPublicKey dhPublicKey) {
        writeData(asUnsignedByteArray(dhPublicKey.getY()));
        return this;
    }

    /**
     * Write the OTRv3 DSA public key to the output stream.
     *
     * @param pubKey the DSA public key
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writePublicKey(@Nonnull final DSAPublicKey pubKey) {
        writeShort(PUBLIC_KEY_TYPE_DSA);
        final DSAParams dsaParams = pubKey.getParams();
        writeBigInt(dsaParams.getP());
        writeBigInt(dsaParams.getQ());
        writeBigInt(dsaParams.getG());
        writeBigInt(pubKey.getY());
        return this;
    }

    /**
     * Write the OTRv3 signature value to the output stream.
     *
     * @param signature the signature
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    @Nonnull
    public OtrOutputStream writeDSASignature(@Nonnull final byte[] signature) {
        this.out.write(signature, 0, signature.length);
        return this;
    }

    /**
     * Write an XSalsa20 nonce.
     *
     * @param nonce The nonce.
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    // FIXME add unit tests.
    @Nonnull
    public OtrOutputStream writeNonce(@Nonnull final byte[] nonce) {
        requireLengthExactly(TYPE_LEN_NONCE, nonce);
        this.out.write(nonce, 0, nonce.length);
        return this;
    }

    /**
     * Write an OTRv4 MAC.
     *
     * @param mac 64-byte MAC as used in OTRv4
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    // FIXME add unit tests.
    @Nonnull
    public OtrOutputStream writeMacOTR4(@Nonnull final byte[] mac) {
        requireLengthExactly(TYPE_LEN_MAC_OTR4, mac);
        this.out.write(mac, 0, mac.length);
        return this;
    }

    /**
     * Write an Edwards point encoded according to RFC8032.
     *
     * @param p The Edwards point.
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    // FIXME add unit tests.
    @Nonnull
    public OtrOutputStream writePoint(@Nonnull final Point p) {
        writeData(p.encode());
        return this;
    }

    /**
     * Write an EdDSA signature.
     *
     * @param signature A signature consisting of exactly 114 bytes is expected.
     * @return Returns this instance of OtrOutputStream such that method calls can be chained.
     */
    // FIXME add unit tests.
    @Nonnull
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
