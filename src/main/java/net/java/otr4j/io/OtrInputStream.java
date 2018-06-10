/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.SignatureX;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.OtrCryptoEngine4.decodePoint;

/**
 * OTR input stream.
 *
 * The input is based on the InputStream type as we take into account any and
 * all possibilities of incomplete or bad data. Many methods throw IOException
 * to indicate for such an illegal situation.
 */
public final class OtrInputStream extends FilterInputStream implements
        SerializationConstants {

    private static final byte[] ZERO_BYTES = new byte[0];

    /**
     * Constant indicating limit for data lengths that are accepted
     * unconditionally. Data lengths read from OtrInputStream that are smaller
     * than this amount will be accepted unconditionally. For any value of the
     * limit or higher, we do additional sanity checking.
     */
    private static final int LIMIT_UNCONDITIONAL_DATA_LENGTH = 65536;

    /**
     * Construct OtrInputStream based on existing, provided source input stream.
     *
     * @param in the source input stream
     */
    public OtrInputStream(@Nonnull final InputStream in) {
        super(in);
    }

    /**
     * Reads from the stream while checking possible border and error conditions
     * like a requested size of zero or the stream does not contain enough data.
     *
     * @param length
     *            amount of bytes to read from the stream
     * @return the read bytes
     * @throws IOException
     *             the exact amount of requested bytes could not be read from
     *             the stream.
     */
    @Nonnull
    private byte[] checkedRead(final int length) throws IOException {
        if (length == 0) {
            return ZERO_BYTES;
        }
        final byte[] b = new byte[length];
        final int bytesRead = read(b);
        if (bytesRead != length) {
            throw new ProtocolException(
                    "Unable to read the required amount of bytes from the stream. Expected were "
                            + length + " bytes but I could only read "
                            + bytesRead + " bytes.");
        }
        return b;
    }

    private int readNumber(final int length) throws IOException {
        final byte[] b = checkedRead(length);

        int value = 0;
        for (int i = 0; i < b.length; i++) {
            final int shift = (b.length - 1 - i) * 8;
            value += (b[i] & 0x000000FF) << shift;
        }

        return value;
    }

    public int readByte() throws IOException {
        return readNumber(TYPE_LEN_BYTE);
    }

    /**
     * Read an integer value from OtrInputStream.
     *
     * NOTE that OTR specifies 4-byte unsigned int values are supported.
     * However, Java by default interprets these values as signed. When using
     * readInt, make sure that your use case will consider negative values and
     * interpret them correctly.
     *
     * @return Returns int value as read from input stream.
     * @throws IOException Throws IOException in case of read errors.
     */
    public int readInt() throws IOException {
        return readNumber(TYPE_LEN_INT);
    }

    public int readShort() throws IOException {
        return readNumber(TYPE_LEN_SHORT);
    }

    @Nonnull
    public byte[] readCtr() throws IOException {
        return checkedRead(TYPE_LEN_CTR);
    }

    @Nonnull
    public byte[] readMac() throws IOException {
        return checkedRead(TYPE_LEN_MAC);
    }

    @Nonnull
    public BigInteger readBigInt() throws IOException {
        final byte[] b = readData();
        return new BigInteger(1, b);
    }

    /**
     * Read data (bytes) from OtrInputStream.
     *
     * NOTE that at this time, the maximum data length supported by otr4j is
     * limited by the Java max. integer size. Data lengths that use full 32
     * bits, will be interpreted as negative values and furthermore array are
     * limited (approx.) to {@link Integer#MAX_VALUE} length. Therefore, any
     * data of length > {@link Integer#MAX_VALUE} will be rejected and
     * {@link UnsupportedLengthException} is thrown.
     *
     * @return Returns byte[] with data read.
     * @throws IOException Throws IOException in case of read errors.
     * @throws UnsupportedLengthException Throws UnsupportedLengthException in
     * case of data with length > {@link Integer#MAX_VALUE}, as this is
     * currently unsupported by otr4j.
     */
    @Nonnull
    public byte[] readData() throws IOException {
        final int dataLen = readNumber(DATA_LEN);
        checkDataLength(dataLen);
        return checkedRead(dataLen);
    }

    /**
     * Read public key from OTR data stream.
     *
     * @return Returns public key components.
     * @throws IOException Throws IOException in case of failing to read full public key from input data.
     * @throws OtrCryptoException Throws OtrCryptoException if failed to reconstruct corresponding public key.
     * @throws UnsupportedTypeException Thrown in case an unsupported public key type is encountered.
     */
    @Nonnull
    public PublicKey readPublicKey() throws IOException, OtrCryptoException, UnsupportedTypeException {
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
     *
     * Apart from reading the DH public key from the byte stream, it also
     * verifies that the public key satisfies all requirements.
     *
     * @return Returns (verified) DH Public Key instance.
     * @throws IOException Throws exception in case of problems while reading DH
     * Public Key instance from input stream.
     * @throws OtrCryptoException Throws exception in case of illegal DH public
     * key.
     */
    @Nonnull
    public DHPublicKey readDHPublicKey() throws IOException, OtrCryptoException {
        final BigInteger gyMpi = readBigInt();
        return OtrCryptoEngine.verify(OtrCryptoEngine.getDHPublicKey(gyMpi));
    }

    @Nonnull
    public byte[] readTlvData() throws IOException {
        final int len = readNumber(TYPE_LEN_SHORT);
        return checkedRead(len);
    }

    @Nonnull
    public byte[] readSignature(@Nonnull final PublicKey pubKey) throws IOException {
        if (!pubKey.getAlgorithm().equals("DSA")) {
            throw new UnsupportedOperationException("Unsupported public key instance type encountered. Cannot read signature.");
        }
        final DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
        final DSAParams dsaParams = dsaPubKey.getParams();
        return checkedRead(dsaParams.getQ().bitLength() / 4);
    }

    /**
     * Read Mysterious X signature data.
     *
     * @return Returns Mysterious X instance.
     * @throws IOException In case of failure in reading the message.
     * @throws OtrCryptoException In case of failures while processing the
     * message content.
     * @throws UnsupportedTypeException In case of unsupported public key type.
     */
    @Nonnull
    public SignatureX readMysteriousX() throws IOException, OtrCryptoException, UnsupportedTypeException {
        final PublicKey pubKey = readPublicKey();
        final int dhKeyID = readInt();
        final byte[] sig = readSignature(pubKey);
        return new SignatureX(pubKey, dhKeyID, sig);
    }

    public long readLong() throws IOException {
        final byte[] b = checkedRead(TYPE_LEN_LONG);
        long value = 0;
        for (int i = 0; i < b.length; i++) {
            final int shift = (b.length - 1 - i) * 8;
            value += ((b[i] & 0xFFL) << shift);
        }
        return value;
    }

    /**
     * Read Ed448 point.
     *
     * @return Returns Ed448 point.
     * @throws IOException        In case of failure to read from input stream.
     * @throws OtrCryptoException In case of failure decoding Point, meaning point data is invalid.
     */
    // FIXME add unit tests.
    @Nonnull
    public Point readPoint() throws IOException, OtrCryptoException {
        return decodePoint(readData());
    }

    /**
     * Read an EdDSA signature payload.
     *
     * @return Returns an EdDSA signature as bytes, expecting exactly 114 bytes.
     * @throws IOException Throws an error in case of failure to read.
     */
    // FIXME add unit tests.
    @Nonnull
    public byte[] readEdDSASignature() throws IOException {
        return checkedRead(EDDSA_SIGNATURE_LENGTH_BYTES);
    }

    /**
     * Sanity check on read data length.
     *
     * In case of an invalid message, it may be possible that the data length is
     * very large. For example, because we interpreted ASCII chars as a number.
     * Do a quick sanity check to ensure that we do allocate massive amounts of
     * memory for a small amount of (bad) message bytes.
     *
     * @param length the requested length to be verified
     */
    private void checkDataLength(final int length) throws IOException {
        if (length < 0) {
            throw new UnsupportedLengthException(length);
        }
        // Note that checking available bytes only works under the assumption
        // that large amounts of available data are known in advance. Since
        // otr4j uses ByteArrayInputStream this is the case. In many other cases
        // this would fail.
        if (length < LIMIT_UNCONDITIONAL_DATA_LENGTH || length <= this.in.available()) {
            // Immediately accept small amounts. Accept larger amounts if at
            // least that amount of data is available to be read.
            return;
        }
        throw new UnverifiableLargeLengthException(length);
    }

    /**
     * Exception indicating that an unsupported length is encountered. This
     * length is currently supported by otr4j due to limitations in its current
     * implementation.
     */
    public static final class UnsupportedLengthException extends IOException {

        private static final long serialVersionUID = 3929379089911298862L;

        private UnsupportedLengthException(final int length) {
            super("An unsupported length is encountered. This is a limitation in the current implementation of otr4j. (Length: " + length + ", should be interpreted as an unsigned int.)");
        }
    }

    /**
     * Exception indicating case where a very large amount of data is requested
     * and it cannot be verified as a necessary/required amount with some sanity
     * checking.
     */
    public static final class UnverifiableLargeLengthException extends IOException {

        private static final long serialVersionUID = 7390243594500513199L;

        private UnverifiableLargeLengthException(final int length) {
            super("Large amount of data requested and not all is immediately available. This is considered an invalid data length. (Length: " + length + ")");
        }
    }
}
