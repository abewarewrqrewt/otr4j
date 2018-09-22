package net.java.otr4j.io;

import net.java.otr4j.api.TLV;
import org.bouncycastle.util.BigIntegers;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOfRange;
import static java.util.Arrays.fill;
import static java.util.Collections.singleton;
import static net.java.otr4j.util.SecureRandoms.random;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.assertArrayEquals;

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
        final byte[] expected = concatenate(new byte[] { 0, 0, 0, 8}, BigIntegers.asUnsignedByteArray(value));
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
        final byte[] mac = random(RANDOM, new byte[20]);
        assertArrayEquals(mac, new OtrOutputStream().writeMac(mac).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteMacNull() {
        new OtrOutputStream().writeMac(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacTooSmall() {
        final byte[] mac = random(RANDOM, new byte[19]);
        new OtrOutputStream().writeMac(mac);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacTooLarge() {
        final byte[] mac = random(RANDOM, new byte[21]);
        new OtrOutputStream().writeMac(mac);
    }

    @Test
    public void testWriteMacOTR4() {
        final byte[] mac = random(RANDOM, new byte[64]);
        assertArrayEquals(mac, new OtrOutputStream().writeMacOTR4(mac).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteMacOTR4Null() {
        new OtrOutputStream().writeMacOTR4(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacOTR4TooSmall() {
        final byte[] mac = random(RANDOM, new byte[63]);
        new OtrOutputStream().writeMacOTR4(mac);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteMacOTR4TooLarge() {
        final byte[] mac = random(RANDOM, new byte[65]);
        new OtrOutputStream().writeMacOTR4(mac);
    }

    @Test
    public void testWriteSSIDOTR4() {
        final byte[] ssid = random(RANDOM, new byte[8]);
        assertArrayEquals(ssid, new OtrOutputStream().writeSSID(ssid).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteSSIDOTR4Null() {
        new OtrOutputStream().writeSSID(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteSSIDOTR4TooSmall() {
        final byte[] ssid = random(RANDOM, new byte[7]);
        new OtrOutputStream().writeSSID(ssid);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteSSIDOTR4TooLarge() {
        final byte[] ssid = random(RANDOM, new byte[9]);
        new OtrOutputStream().writeSSID(ssid);
    }

    @Test
    public void testWriteFingerprint() {
        final byte[] fingerprint = random(RANDOM, new byte[56]);
        assertArrayEquals(fingerprint, new OtrOutputStream().writeFingerprint(fingerprint).toByteArray());
    }

    @Test(expected = NullPointerException.class)
    public void testWriteFingerprintNull() {
        new OtrOutputStream().writeFingerprint(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteFingerprintTooSmall() {
        final byte[] fingerprint = random(RANDOM, new byte[57]);
        new OtrOutputStream().writeFingerprint(fingerprint);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteFingerprintTooLarge() {
        final byte[] fingerprint = random(RANDOM, new byte[55]);
        new OtrOutputStream().writeFingerprint(fingerprint);
    }

    @Test(expected = NullPointerException.class)
    public void testWriteCtrNull() {
        new OtrOutputStream().writeCtr(null);
    }

    @Test
    public void testWriteCtr() {
        final byte[] ctr = random(RANDOM, new byte[8]);
        assertArrayEquals(ctr, new OtrOutputStream().writeCtr(ctr).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteCtrTooSmall() {
        final byte[] ctr = random(RANDOM, new byte[7]);
        new OtrOutputStream().writeCtr(ctr);
    }

    @Test
    public void testWriteCtrAsInOTRv3() {
        final byte[] ctr = random(RANDOM, new byte[16]);
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
        final byte[] nonce = random(RANDOM, new byte[24]);
        assertArrayEquals(nonce, new OtrOutputStream().writeNonce(nonce).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteNonceTooSmall() {
        final byte[] nonce = random(RANDOM, new byte[23]);
        new OtrOutputStream().writeNonce(nonce);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteNonceTooLarge() {
        final byte[] nonce = random(RANDOM, new byte[25]);
        new OtrOutputStream().writeNonce(nonce);
    }

    @Test(expected = NullPointerException.class)
    public void testWriteEdDSASignatureNull() {
        new OtrOutputStream().writeEdDSASignature(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteEdDSASignatureTooSmall() {
        final byte[] signature = random(RANDOM, new byte[113]);
        new OtrOutputStream().writeEdDSASignature(signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteEdDSASignatureTooLarge() {
        final byte[] signature = random(RANDOM, new byte[115]);
        new OtrOutputStream().writeEdDSASignature(signature);
    }

    @Test
    public void testWriteEdDSASignature() {
        final byte[] signature = random(RANDOM, new byte[114]);
        assertArrayEquals(signature, new OtrOutputStream().writeEdDSASignature(signature).toByteArray());
    }
}
