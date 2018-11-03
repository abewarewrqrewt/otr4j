/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalars;
import net.java.otr4j.crypto.ed448.ValidationException;
import org.junit.Test;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.math.BigInteger.valueOf;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOfRange;
import static java.util.Arrays.fill;
import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public class OtrOutputStreamTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final ByteArrayOutputStream out = new ByteArrayOutputStream();

    @Test
    public void testConstruction() {
        new OtrOutputStream();
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullOutputStream() {
        new OtrOutputStream(null);
    }

    @Test
    public void testConstructOtrOutputStream() {
        new OtrOutputStream(out);
    }

    @Test
    public void testProduceEmptyResult() {
        assertArrayEquals(new byte[0], new OtrOutputStream().toByteArray());
    }

    @Test
    public void testProduceDataResult() {
        final byte[] data = new byte[20];
        RANDOM.nextBytes(data);
        assertArrayEquals(concatenate(new byte[]{0, 0, 0, 20}, data),
            new OtrOutputStream().writeData(data).toByteArray());
    }

    @Test
    public void testProduceBigIntResult() {
        final BigInteger value = new BigInteger("9876543211234567890");
        final byte[] expected = concatenate(new byte[] { 0, 0, 0, 8}, asUnsignedByteArray(value));
        assertArrayEquals(expected, new OtrOutputStream().writeBigInt(value).toByteArray());
    }

    @Test
    public void testProduceShortResult() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff},
            new OtrOutputStream().writeShort(0xffff).toByteArray());
    }

    @Test
    public void testProduceShortResultOverflowing() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff},
            new OtrOutputStream().writeShort(0x0001ffff).toByteArray());
    }

    @Test
    public void testProduceIntResult() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new OtrOutputStream().writeInt(0xffffffff).toByteArray());
    }

    @Test
    public void testProduceByteResult() {
        final byte value = (byte) 0xf5;
        assertArrayEquals(new byte[] {value}, new OtrOutputStream().writeByte(value).toByteArray());
    }

    @Test
    public void testProduceLongResult() {
        final long value = RANDOM.nextLong();
        final byte[] expected = new byte[]{
            (byte) ((value & 0xff00000000000000L) >>> 56),
            (byte) ((value & 0xff000000000000L) >>> 48),
            (byte) ((value & 0xff0000000000L) >>> 40),
            (byte) ((value & 0xff00000000L) >>> 32),
            (byte) ((value & 0xff000000L) >>> 24),
            (byte) ((value & 0xff0000L) >>> 16),
            (byte) ((value & 0xff00L) >>> 8),
            (byte) (value & 0xffL)};
        assertArrayEquals(expected, new OtrOutputStream().writeLong(value).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteEncodableNull() {
        new OtrOutputStream().write(null);
    }

    @Test
    public void testWriteEncodable() {
        final byte[] data = "Hello world!".getBytes(UTF_8);
        final byte[] expected = concatenate(new byte[]{0, 0, 0, 0xc}, data);
        final byte[] result = new OtrOutputStream().write(new OtrEncodable() {
            @Override
            public void writeTo(@Nonnull final OtrOutputStream out) {
                out.writeData(data);
            }
        }).toByteArray();
        assertArrayEquals(expected, result);
    }

    @Test(expected = NullPointerException.class)
    public void testWriteNullMessage() {
        new OtrOutputStream().writeMessage(null);
    }

    @Test
    public void testWriteEmptyMessage() {
        assertArrayEquals(new byte[0], new OtrOutputStream().writeMessage("").toByteArray());
    }

    @Test
    public void testWriteMessage() {
        assertArrayEquals("Hello plaintext".getBytes(UTF_8),
            new OtrOutputStream().writeMessage("Hello plaintext").toByteArray());
    }

    @Test
    public void testWriteMessageContainingNulls() {
        assertArrayEquals("Hello ??? plaintext?".getBytes(UTF_8),
            new OtrOutputStream().writeMessage("Hello \0\0\0 plaintext\0").toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteNullTLVs() {
        new OtrOutputStream().writeTLV(null);
    }

    @Test
    public void testWriteEmptyTLVs() {
        assertArrayEquals(new byte[0], new OtrOutputStream().writeTLV(Collections.<TLV>emptyList()).toByteArray());
    }

    @Test
    public void testWriteSingleTLV() {
        final byte[] helloWorldBytes = "hello world".getBytes(UTF_8);
        final TLV tlv = new TLV(55, helloWorldBytes);
        assertArrayEquals(concatenate(new byte[]{0x00, 0x37, 0x00, 0x0B}, helloWorldBytes),
            new OtrOutputStream().writeTLV(singleton(tlv)).toByteArray());
    }

    @Test
    public void testWriteMultipleTLVs() {
        final byte[] helloWorldBytes = "hello world".getBytes(UTF_8);
        final byte[] expected = concatenate(new byte[]{0x00, 0x37, 0x00, 0x0B}, helloWorldBytes,
            new byte[]{0x00, 0x0B, 0x00, 0x00}, new byte[]{0x00, 0x01, 0x00, 0x02, 'h', 'i'});
        final List<TLV> tlvs = Arrays.asList(new TLV(55, helloWorldBytes), new TLV(11, new byte[0]),
            new TLV(1, new byte[]{'h', 'i'}));
        assertArrayEquals(expected, new OtrOutputStream().writeTLV(tlvs).toByteArray());
    }

    @Test
    public void testWriteMac() {
        final byte[] mac = randomBytes(RANDOM, new byte[20]);
        assertArrayEquals(mac, new OtrOutputStream().writeMac(mac).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteMacNull() {
        new OtrOutputStream().writeMac(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacTooSmall() {
        final byte[] mac = randomBytes(RANDOM, new byte[19]);
        new OtrOutputStream().writeMac(mac);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacTooLarge() {
        final byte[] mac = randomBytes(RANDOM, new byte[21]);
        new OtrOutputStream().writeMac(mac);
    }

    @Test
    public void testWriteMacOTR4() {
        final byte[] mac = randomBytes(RANDOM, new byte[64]);
        assertArrayEquals(mac, new OtrOutputStream().writeMacOTR4(mac).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteMacOTR4Null() {
        new OtrOutputStream().writeMacOTR4(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacOTR4TooSmall() {
        final byte[] mac = randomBytes(RANDOM, new byte[63]);
        new OtrOutputStream().writeMacOTR4(mac);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacOTR4TooLarge() {
        final byte[] mac = randomBytes(RANDOM, new byte[65]);
        new OtrOutputStream().writeMacOTR4(mac);
    }

    @Test
    public void testWriteSSIDOTR4() {
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        assertArrayEquals(ssid, new OtrOutputStream().writeSSID(ssid).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteSSIDOTR4Null() {
        new OtrOutputStream().writeSSID(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteSSIDOTR4TooSmall() {
        final byte[] ssid = randomBytes(RANDOM, new byte[7]);
        new OtrOutputStream().writeSSID(ssid);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteSSIDOTR4TooLarge() {
        final byte[] ssid = randomBytes(RANDOM, new byte[9]);
        new OtrOutputStream().writeSSID(ssid);
    }

    @Test
    public void testWriteFingerprint() {
        final byte[] fingerprint = randomBytes(RANDOM, new byte[56]);
        assertArrayEquals(fingerprint, new OtrOutputStream().writeFingerprint(fingerprint).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteFingerprintNull() {
        new OtrOutputStream().writeFingerprint(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteFingerprintTooSmall() {
        final byte[] fingerprint = randomBytes(RANDOM, new byte[57]);
        new OtrOutputStream().writeFingerprint(fingerprint);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteFingerprintTooLarge() {
        final byte[] fingerprint = randomBytes(RANDOM, new byte[55]);
        new OtrOutputStream().writeFingerprint(fingerprint);
    }

    @Test(expected = NullPointerException.class)
    public void testWriteCtrNull() {
        new OtrOutputStream().writeCtr(null);
    }

    @Test
    public void testWriteCtr() {
        final byte[] ctr = randomBytes(RANDOM, new byte[8]);
        assertArrayEquals(ctr, new OtrOutputStream().writeCtr(ctr).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteCtrTooSmall() {
        final byte[] ctr = randomBytes(RANDOM, new byte[7]);
        new OtrOutputStream().writeCtr(ctr);
    }

    @Test
    public void testWriteCtrAsInOTRv3() {
        final byte[] ctr = randomBytes(RANDOM, new byte[16]);
        fill(ctr, 8, 16, (byte) 0);
        final byte[] expected = copyOfRange(ctr, 0, 8);
        assertArrayEquals(expected, new OtrOutputStream().writeCtr(ctr).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteNonceNull() {
        new OtrOutputStream().writeNonce(null);
    }

    @Test
    public void testWriteNonce() {
        final byte[] nonce = randomBytes(RANDOM, new byte[24]);
        assertArrayEquals(nonce, new OtrOutputStream().writeNonce(nonce).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteNonceTooSmall() {
        final byte[] nonce = randomBytes(RANDOM, new byte[23]);
        new OtrOutputStream().writeNonce(nonce);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteNonceTooLarge() {
        final byte[] nonce = randomBytes(RANDOM, new byte[25]);
        new OtrOutputStream().writeNonce(nonce);
    }

    @Test(expected = NullPointerException.class)
    public void testWriteEdDSASignatureNull() {
        new OtrOutputStream().writeEdDSASignature(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteEdDSASignatureTooSmall() {
        final byte[] signature = randomBytes(RANDOM, new byte[113]);
        new OtrOutputStream().writeEdDSASignature(signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteEdDSASignatureTooLarge() {
        final byte[] signature = randomBytes(RANDOM, new byte[115]);
        new OtrOutputStream().writeEdDSASignature(signature);
    }

    @Test
    public void testWriteEdDSASignature() {
        final byte[] signature = randomBytes(RANDOM, new byte[114]);
        assertArrayEquals(signature, new OtrOutputStream().writeEdDSASignature(signature).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteScalarNull() {
        new OtrOutputStream().writeScalar(null);
    }

    @Test
    public void testWriteScalar() {
        final byte[] expected = new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        assertArrayEquals(expected, new OtrOutputStream().writeScalar(Scalars.one()).toByteArray());
    }

    @Test
    public void testWriteScalar2() {
        final byte[] expected = new byte[] {(byte) 0x8f, 0, (byte) 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        assertArrayEquals(expected, new OtrOutputStream().writeScalar(fromBigInteger(valueOf(16711823L))).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWritePointNull() {
        new OtrOutputStream().writePoint(null);
    }

    @Test
    public void testWritePointWithPositiveX() throws ValidationException {
        final byte[] expected = new byte[]{(byte) 0xa8, 0x1b, 0x2e, (byte) 0x8a, 0x70, (byte) 0xa5, (byte) 0xac, (byte) 0x94, (byte) 0xff, (byte) 0xdb, (byte) 0xcc, (byte) 0x9b, (byte) 0xad, (byte) 0xfc, 0x3f, (byte) 0xeb, 0x08, 0x01, (byte) 0xf2, 0x58, 0x57, (byte) 0x8b, (byte) 0xb1, 0x14, (byte) 0xad, 0x44, (byte) 0xec, (byte) 0xe1, (byte) 0xec, 0x0e, 0x79, (byte) 0x9d, (byte) 0xa0, (byte) 0x8e, (byte) 0xff, (byte) 0xb8, 0x1c, 0x5d, 0x68, 0x5c, 0x0c, 0x56, (byte) 0xf6, 0x4e, (byte) 0xec, (byte) 0xae, (byte) 0xf8, (byte) 0xcd, (byte) 0xf1, 0x1c, (byte) 0xc3, (byte) 0x87, 0x37, (byte) 0x83, (byte) 0x8c, (byte) 0xf4, 0x00};
        final Point p = decodePoint(expected);
        assertArrayEquals(expected, new OtrOutputStream().writePoint(p).toByteArray());
    }

    @Test
    public void testWritePointWithNegativeX() throws ValidationException {
        final byte[] expected = new byte[] {(byte) 0xb3, (byte) 0xda, 0x07, (byte) 0x9b, 0x0a, (byte) 0xa4, (byte) 0x93, (byte) 0xa5, 0x77, 0x20, 0x29, (byte) 0xf0, 0x46, 0x7b, (byte) 0xae, (byte) 0xbe, (byte) 0xe5, (byte) 0xa8, 0x11, 0x2d, (byte) 0x9d, 0x3a, 0x22, 0x53, 0x23, 0x61, (byte) 0xda, 0x29, 0x4f, 0x7b, (byte) 0xb3, (byte) 0x81, 0x5c, 0x5d, (byte) 0xc5, (byte) 0x9e, 0x17, 0x6b, 0x4d, (byte) 0x9f, 0x38, 0x1c, (byte) 0xa0, (byte) 0x93, (byte) 0x8e, 0x13, (byte) 0xc6, (byte) 0xc0, 0x7b, 0x17, 0x4b, (byte) 0xe6, 0x5d, (byte) 0xfa, 0x57, (byte) 0x8e, (byte) 0x80};
        final Point p = decodePoint(expected);
        assertArrayEquals(expected, new OtrOutputStream().writePoint(p).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteDSASignatureNull() {
        new OtrOutputStream().writeDSASignature(null);
    }

    @Test
    public void testWriteDSASignature() {
        final byte[] signature = randomBytes(RANDOM, new byte[20]);
        assertArrayEquals(signature, new OtrOutputStream().writeDSASignature(signature).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteDSAPublicKeyNull() {
        new OtrOutputStream().writePublicKey(null);
    }

    @Test
    public void testWriteDSAPublicKey() throws ProtocolException {
        final DSAPublicKey publicKey = generateDSAKeyPair().getPublic();
        final byte[] result = new OtrOutputStream().writePublicKey(publicKey).toByteArray();
        final OtrInputStream in = new OtrInputStream(result);
        assertEquals(0, in.readShort());
        assertEquals(publicKey.getParams().getP(), in.readBigInt());
        assertEquals(publicKey.getParams().getQ(), in.readBigInt());
        assertEquals(publicKey.getParams().getG(), in.readBigInt());
        assertEquals(publicKey.getY(), in.readBigInt());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteDHPublicKeyNull() {
        new OtrOutputStream().writeDHPublicKey(null);
    }

    @Test
    public void testWriteDHPublicKey() throws OtrInputStream.UnsupportedLengthException, ProtocolException {
        final DHPublicKey publicKey = generateDHKeyPair(RANDOM).getPublic();
        final byte[] result = new OtrOutputStream().writeDHPublicKey(publicKey).toByteArray();
        final byte[] publicKeyBytes = asUnsignedByteArray(publicKey.getY());
        assertArrayEquals(publicKeyBytes, new OtrInputStream(result).readData());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteInstanceTagNull() {
        new OtrOutputStream().writeInstanceTag(null);
    }

    @Test
    public void testWriteInstanceTag() {
        assertArrayEquals(new byte[] {0, 0, 1, 0}, new OtrOutputStream().writeInstanceTag(SMALLEST_TAG).toByteArray());
    }

    @Test
    public void testWriteInstanceTagZero() {
        assertArrayEquals(new byte[] {0, 0, 0, 0}, new OtrOutputStream().writeInstanceTag(ZERO_TAG).toByteArray());
    }

    @Test
    public void testWriteInstanceTagHighest() {
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}, new OtrOutputStream().writeInstanceTag(HIGHEST_TAG).toByteArray());
    }

    @Test
    public void testWriteInstanceTagArbitraryValue() throws ProtocolException {
        final InstanceTag expectedTag = InstanceTag.random(RANDOM);
        final InstanceTag readTag = new OtrInputStream(new OtrOutputStream().writeInstanceTag(expectedTag).toByteArray())
                .readInstanceTag();
        assertEquals(expectedTag, readTag);
    }
}
