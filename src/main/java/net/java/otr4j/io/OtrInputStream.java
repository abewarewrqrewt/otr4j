/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decodePoint;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.io.EncodingConstants.DATA_LEN;
import static net.java.otr4j.io.EncodingConstants.EDDSA_SIGNATURE_LENGTH_BYTES;
import static net.java.otr4j.io.EncodingConstants.POINT_LENGTH_BYTES;
import static net.java.otr4j.io.EncodingConstants.PUBLIC_KEY_TYPE_DSA;
import static net.java.otr4j.io.EncodingConstants.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_BYTE;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_CTR;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_INT;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_LONG;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_MAC;
import static net.java.otr4j.io.EncodingConstants.MAC_OTR4_LENGTH_BYTES;
import static net.java.otr4j.io.EncodingConstants.NONCE_LENGTH_BYTES;
import static net.java.otr4j.io.EncodingConstants.TYPE_LEN_SHORT;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;

/**
 * OTR input stream.
 * <p>
 * The input is based on the InputStream type as we take into account any and all possibilities of incomplete or bad
 * data. Many methods throw ProtocolException to indicate for such an illegal situation.
 * <p>
 * OtrInputStream provides only for the primitive types to be read. Composite objects should be read through use of the
 * primitive read methods and implemented outside of this class.
 */
public final class OtrInputStream {

    private static final byte[] ZERO_BYTES = new byte[0];

    private final ByteArrayInputStream in;

    /**
     * Construct OtrInputStream based on existing, provided source input stream.
     *
     * @param in the source input stream
     */
    public OtrInputStream(@Nonnull final byte[] in) {
        this.in = new ByteArrayInputStream(in);
    }

    /**
     * Available number of bytes of content.
     *
     * @return Returns number of available bytes.
     */
    public int available() {
        return this.in.available();
    }

    /**
     * Read byte.
     *
     * @return Returns read byte.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    public byte readByte() throws ProtocolException {
        return (byte) readNumber(TYPE_LEN_BYTE);
    }

    /**
     * Read an integer value from OtrInputStream.
     * <p>
     * NOTE that OTR specifies 4-byte unsigned int values are supported.
     * However, Java by default interprets these values as signed. When using
     * readInt, make sure that your use case will consider negative values and
     * interpret them correctly.
     *
     * @return Returns int value as read from input stream.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    public int readInt() throws ProtocolException {
        return readNumber(TYPE_LEN_INT);
    }

    /**
     * Read short.
     *
     * @return Returns short value.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    public int readShort() throws ProtocolException {
        return readNumber(TYPE_LEN_SHORT);
    }

    /**
     * Read instance tag.
     *
     * @return Returns the instance tag.
     * @throws ProtocolException In case of failure to read instance tag value from input stream.
     */
    @Nonnull
    public InstanceTag readInstanceTag() throws ProtocolException {
        final int value = readInt();
        if (!isValidInstanceTag(value)) {
            throw new ProtocolException("Illegal instance tag encountered.");
        }
        return new InstanceTag(value);
    }

    /**
     * Read counter value from message stream.
     *
     * @return Returns counter value.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    @Nonnull
    public byte[] readCtr() throws ProtocolException {
        return checkedRead(TYPE_LEN_CTR);
    }

    /**
     * Read OTRv3 MAC value from message stream.
     *
     * @return Returns MAC value.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    @Nonnull
    public byte[] readMac() throws ProtocolException {
        return checkedRead(TYPE_LEN_MAC);
    }

    /**
     * Read an Big Integer (MPI) value from the OTR input stream.
     *
     * @return Returns MPI value as Big Integer.
     * @throws ProtocolException In case of bad input data resulting in failure to parse Big Integer value.
     */
    @Nonnull
    public BigInteger readBigInt() throws ProtocolException {
        try {
            final byte[] b = readData();
            return new BigInteger(1, b);
        } catch (final UnsupportedLengthException e) {
            throw new ProtocolException("Unexpectedly large MPI value encountered. This is most likely not according to specification.");
        }
    }

    /**
     * Read data (bytes) from OtrInputStream.
     * <p>
     * NOTE that at this time, the maximum data length supported by otr4j is
     * limited by the Java max. integer size. Data lengths that use full 32
     * bits, will be interpreted as negative values and furthermore array are
     * limited (approx.) to {@link Integer#MAX_VALUE} length. Therefore, any
     * data of length &gt; {@link Integer#MAX_VALUE} will be rejected and
     * {@link UnsupportedLengthException} is thrown.
     *
     * @return Returns byte[] with data read.
     * @throws ProtocolException          Throws IOException in case of read errors.
     * @throws UnsupportedLengthException Throws UnsupportedLengthException in
     *                                    case of data with length &gt; {@link Integer#MAX_VALUE}, as this is
     *                                    currently unsupported by otr4j.
     */
    @Nonnull
    public byte[] readData() throws ProtocolException, UnsupportedLengthException {
        final int dataLen = checkDataLength(readNumber(DATA_LEN));
        return checkedRead(dataLen);
    }

    /**
     * Read public key from OTR data stream.
     *
     * @return Returns public key components.
     * @throws ProtocolException          Throws IOException in case of failing to read full public key from input data.
     * @throws OtrCryptoException         Throws OtrCryptoException if failed to reconstruct corresponding public key.
     * @throws UnsupportedTypeException   Thrown in case an unsupported public key type is encountered.
     */
    @Nonnull
    public DSAPublicKey readPublicKey() throws OtrCryptoException, UnsupportedTypeException, ProtocolException {
        final int type = readShort();
        switch (type) {
        case PUBLIC_KEY_TYPE_DSA:
            final BigInteger p = readBigInt();
            final BigInteger q = readBigInt();
            final BigInteger g = readBigInt();
            final BigInteger y = readBigInt();
            return OtrCryptoEngine.createDSAPublicKey(y, p, q, g);
        default:
            throw new UnsupportedTypeException("Unsupported type for public key: " + type);
        }
    }

    /**
     * Read DH Public Key from the input stream.
     * <p>
     * Apart from reading the DH public key from the byte stream, it also
     * verifies that the public key satisfies all requirements.
     *
     * @return Returns (verified) DH Public Key instance.
     * @throws ProtocolException          Throws exception in case of problems while reading DH
     *                                    Public Key instance from input stream.
     * @throws OtrCryptoException         Throws exception in case of illegal DH public
     *                                    key.
     */
    @Nonnull
    public DHPublicKey readDHPublicKey() throws OtrCryptoException, ProtocolException {
        final BigInteger gyMpi = readBigInt();
        return OtrCryptoEngine.verify(OtrCryptoEngine.getDHPublicKey(gyMpi));
    }

    /**
     * Read TLV from message stream.
     *
     * @return Returns TLV value.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    @Nonnull
    public TLV readTLV() throws ProtocolException {
        return new TLV(readShort(), readTlvData());
    }

    /**
     * Read TLV length- and value-part from message stream.
     *
     * @return Returns TLV data, i.e. the TLV value only.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    @Nonnull
    private byte[] readTlvData() throws ProtocolException {
        final int len = readNumber(TYPE_LEN_SHORT);
        return checkedRead(len);
    }

    /**
     * Read signature from message stream.
     *
     * @param pubKey The public key.
     * @return Returns the read signature.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    @Nonnull
    public byte[] readSignature(@Nonnull final PublicKey pubKey) throws ProtocolException {
        if (!pubKey.getAlgorithm().equals("DSA")) {
            throw new UnsupportedOperationException("Unsupported public key instance type encountered. Cannot read signature.");
        }
        final DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
        final DSAParams dsaParams = dsaPubKey.getParams();
        return checkedRead(dsaParams.getQ().bitLength() / 4);
    }

    /**
     * Read long value from message stream.
     *
     * @return Returns long value.
     * @throws ProtocolException In case of unexpected content in the message stream.
     */
    public long readLong() throws ProtocolException {
        final byte[] b = checkedRead(TYPE_LEN_LONG);
        long value = 0;
        for (int i = 0; i < b.length; i++) {
            final int shift = (b.length - 1 - i) * 8;
            value += (b[i] & 0xFFL) << shift;
        }
        return value;
    }

    /**
     * Read XSalsa20 nonce.
     *
     * @return Returns XSalsa20 nonce.
     * @throws ProtocolException In case of failure to read nonce.
     */
    @Nonnull
    public byte[] readNonce() throws ProtocolException {
        return checkedRead(NONCE_LENGTH_BYTES);
    }

    /**
     * Read OTRv4 MAC.
     *
     * @return Returns MAC.
     * @throws ProtocolException In case of failure to read OTRv4 MAC.
     */
    @Nonnull
    public byte[] readMacOTR4() throws ProtocolException {
        return checkedRead(MAC_OTR4_LENGTH_BYTES);
    }

    /**
     * Read Ed448 point.
     *
     * @return Returns Ed448 point.
     * @throws ProtocolException  In case of failure to read from input stream.
     * @throws OtrCryptoException In case of failure decoding Point, meaning point data is invalid.
     */
    @Nonnull
    public Point readPoint() throws OtrCryptoException, ProtocolException {
        return decodePoint(checkedRead(POINT_LENGTH_BYTES));
    }

    /**
     * Read OTRv4 SCALAR value.
     *
     * @return Returns Ed448 SCALAR value.
     * @throws ProtocolException In case of failure to read SCALAR from input stream.
     */
    @Nonnull
    public BigInteger readScalar() throws ProtocolException {
        return decodeLittleEndian(checkedRead(SCALAR_LENGTH_BYTES)).mod(primeOrder());
    }

    /**
     * Read an EdDSA signature payload.
     *
     * @return Returns an EdDSA signature as bytes, expecting exactly 114 bytes.
     * @throws ProtocolException Throws an error in case of failure to read.
     */
    @Nonnull
    public byte[] readEdDSASignature() throws ProtocolException {
        return checkedRead(EDDSA_SIGNATURE_LENGTH_BYTES);
    }

    /**
     * Read a number of specified length from the input stream.
     *
     * @param length The length to read.
     * @return Returns the read value in bytes.
     * @throws ProtocolException In case of failure to read specified amount of bytes.
     */
    private int readNumber(final int length) throws ProtocolException {
        final byte[] b = checkedRead(length);

        int value = 0;
        for (int i = 0; i < b.length; i++) {
            final int shift = (b.length - 1 - i) * 8;
            value += (b[i] & 0x000000FF) << shift;
        }

        return value;
    }

    /**
     * Reads from the stream while checking possible border and error conditions
     * like a requested size of zero or the stream does not contain enough data.
     *
     * @param length amount of bytes to read from the stream
     * @return the read bytes
     * @throws ProtocolException the exact amount of requested bytes could not be read from
     *                           the stream.
     */
    @Nonnull
    private byte[] checkedRead(final int length) throws ProtocolException {
        if (length == 0) {
            return ZERO_BYTES;
        }
        final byte[] b = new byte[length];
        final int bytesRead = this.in.read(b, 0, b.length);
        if (bytesRead != length) {
            throw new ProtocolException("Unable to read the required amount of bytes from the stream. Expected were "
                + length + " bytes but I could only read " + bytesRead + " bytes.");
        }
        return b;
    }

    /**
     * Sanity check on read data length.
     * <p>
     * In case of an invalid message, it may be possible that the data length is
     * very large. For example, because we interpreted ASCII chars as a number.
     * Do a quick sanity check to ensure that we do allocate massive amounts of
     * memory for a small amount of (bad) message bytes.
     *
     * @param length the requested length to be verified
     * @throws ProtocolException          In case the length read from the data field does not match with the remaining
     *                                    amount of data available in the buffer.
     * @throws UnsupportedLengthException In case a length of over 31 bits is received. This is not supported due to
     *                                    Java interpreting these values as negative by default.
     */
    private int checkDataLength(final int length) throws UnsupportedLengthException, ProtocolException {
        if (length < 0) {
            // 'length < 0' may reasonably happen because Java interprets 32-bit values as signed 31-bit values. otr4j
            // does not support values with lengths over 31 bits, due to this restriction in Java. Since there are no
            // common use cases who suffer due to this limitation, it remains unfixed for now.
            throw new UnsupportedLengthException(length);
        }
        final int available = this.in.available();
        if (length > available) {
            throw new ProtocolException("Insufficient data in buffer for the length specified in the data field. (Specified: "
                + length + ", available: " + available);
        }
        return length;
    }

    /**
     * Exception indicating that an unsupported length is encountered. This
     * length is currently supported by otr4j due to limitations in its current
     * implementation.
     */
    public static final class UnsupportedLengthException extends OtrException {

        private static final long serialVersionUID = 3929379089911298862L;

        private UnsupportedLengthException(final int length) {
            super("An unsupported length is encountered. This is a limitation in the current implementation of otr4j. (Length: " + length + ", should be interpreted as an unsigned int.)");
        }
    }
}
