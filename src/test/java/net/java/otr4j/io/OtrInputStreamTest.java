/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.messages.SignatureX;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for OtrInputStream.
 *
 * Some of these tests are set up to test the limitations of (signed) ints in
 * otr4j implementation.
 *
 * @author Danny van Heumen
 */
public class OtrInputStreamTest {

    private final static SecureRandom RANDOM = new SecureRandom();

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private final EdDSAKeyPair keypair = EdDSAKeyPair.generate(RANDOM);

    @Test
    public void testDataLengthOkay() throws UnsupportedLengthException, ProtocolException {
        final byte[] data = new byte[] { 0, 0, 0, 1, 0x6a };
        final OtrInputStream ois = new OtrInputStream(data);
        assertArrayEquals(new byte[] { 0x6a }, ois.readData());
    }

    @Test(expected = UnsupportedLengthException.class)
    public void testDataLengthTooLarge() throws UnsupportedLengthException, ProtocolException {
        // Verify that the limitation of Java's signed int is in place as
        // expected. 0xffffffff is too large and would have been interpreted as
        // a negative value, thus a negative array size for the byte[]
        // containing the upcoming data.
        // Here we verify that the predefined exception for this particular case
        // is thrown to signal the occurrence of a data value that is too large
        // for otr4j to handle. (This is a limitation of otr4j.)
        final byte[] data = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
        final OtrInputStream ois = new OtrInputStream(data);
        ois.readData();
    }

    @Test
    public void testReadByte() throws ProtocolException {
        final byte[] data = new byte[] { 0x20 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertEquals(' ', ois.readByte());
    }

    @Test(expected = ProtocolException.class)
    public void testReadByteEmptyBuffer() throws ProtocolException {
        final byte[] data = new byte[0];
        final OtrInputStream ois = new OtrInputStream(data);
        ois.readByte();
    }

    @Test(expected = ProtocolException.class)
    public void testReadIntInsufficientData() throws ProtocolException {
        final byte[] data = new byte[] { 0x1, 0x2, 0x3 };
        final OtrInputStream ois = new OtrInputStream(data);
        ois.readInt();
    }

    @Test
    public void testReadInt() throws ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x10 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertEquals(16, ois.readInt());
        assertEquals(0, ois.available());
    }

    @Test
    public void testReadIntDataLeft() throws ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x10, 0x3f};
        final OtrInputStream ois = new OtrInputStream(data);
        assertEquals(16, ois.readInt());
        assertEquals(1, ois.available());
    }

    @Test
    public void testReadShorts() throws ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0, 0xf, 0x0, 0x3f};
        final OtrInputStream ois = new OtrInputStream(data);
        assertEquals(0, ois.readShort());
        assertEquals(3840, ois.readShort());
        assertEquals(1, ois.available());
    }

    @Test
    public void testReadCounter() throws ProtocolException {
        final byte[] data = new byte[] { 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertArrayEquals(data, ois.readCtr());
    }

    @Test
    public void testReadMAC() throws ProtocolException {
        final byte[] data = new byte[] { 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertArrayEquals(data, ois.readMac());
    }

    @Test
    public void testReadBigInteger() throws ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x1, 0x55 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertEquals(BigInteger.valueOf(85L), ois.readBigInt());
    }

    @Test(expected = UnsupportedTypeException.class)
    public void testReadBadPublicKeyType() throws OtrCryptoException, UnsupportedTypeException, ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x55 };
        final OtrInputStream ois = new OtrInputStream(data);
        ois.readPublicKey();
    }

    @Test
    public void testReadPUblicKeyType() throws OtrCryptoException, UnsupportedTypeException, ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x1, 0x2, 0x0, 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, 0x0, 0x1, 0x4 };
        final OtrInputStream ois = new OtrInputStream(data);
        final PublicKey key = ois.readPublicKey();
        assertNotNull(key);
    }

    @Test
    public void testReadDHPublicKeyType() throws OtrCryptoException, ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x1, 0x55 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertEquals(OtrCryptoEngine.getDHPublicKey(BigInteger.valueOf(0x55)), ois.readDHPublicKey());
    }

    @Test(expected = ProtocolException.class)
    public void testReadBadDHPublicKeyType() throws OtrCryptoException, ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x0 };
        final OtrInputStream ois = new OtrInputStream(data);
        ois.readDHPublicKey();
    }

    @Test
    public void testReadTLV() throws ProtocolException {
        final byte[] data = new byte[] { 0x0, 0x2, 0x1, 0x2 };
        final OtrInputStream ois = new OtrInputStream(data);
        assertArrayEquals(new byte[] { 0x1, 0x2 }, ois.readTlvData());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testReadSignatureBadPublicKey() throws ProtocolException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final OtrInputStream ois = new OtrInputStream(new byte[0]);
        ois.readSignature(keypair.getPublic());
    }

    @Test
    public void testReadSignature() throws NoSuchAlgorithmException, NoSuchProviderException, ProtocolException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(1024);
        final KeyPair keypair = keyGen.generateKeyPair();
        final byte[] data = new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };
        final OtrInputStream ois = new OtrInputStream(data);
        assertArrayEquals(data, ois.readSignature(keypair.getPublic()));
    }

    @Test
    public void testReadMysteriousXOtrInputStreamReadBehavior() throws OtrCryptoException, UnsupportedTypeException, ProtocolException {
        // This test uses nonsensicle data and as such it does not verify
        // correct parsing of the read public key material. However, it does
        // test the reading behavior of OtrInputStream expected for such a read
        // operation.
        final byte[] data = new byte[] {
            0, 0, // public key -> type
            0, 0, 0, 1, // public key -> p -> size
            1, // public key -> p
            0, 0, 0, 1, // public key -> q -> size
            16, // public key -> q (needs certain size such that signature of public key has length > 0)
            0, 0, 0, 1, // public key -> g -> size
            3, // public key -> g
            0, 0, 0, 1, // public key -> y -> size
            4, // public key -> y
            0, 0, 0, 5, // dhKeyID
            8, // read signature of public key
        };
        final OtrInputStream ois = new OtrInputStream(data);
        final SignatureX sigX = ois.readMysteriousX();
        assertNotNull(sigX);
        assertNotNull(sigX.longTermPublicKey);
        assertEquals(5, sigX.dhKeyID);
        assertNotNull(sigX.signature);
        assertArrayEquals(new byte[] { 8 }, sigX.signature);
    }

    @Test
    public void testReadLong() throws ProtocolException {
        final long expected = Long.MAX_VALUE;
        final byte[] data = new byte[] {127, -1, -1, -1, -1, -1, -1, -1};
        final OtrInputStream in = new OtrInputStream(data);
        assertEquals(expected, in.readLong());
    }

    @Test(expected = ProtocolException.class)
    public void testReadNonce() throws ProtocolException {
        final OtrInputStream in = new OtrInputStream(new byte[23]);
        in.readNonce();
    }

    @Test
    public void testReadNonceAllZero() throws ProtocolException {
        final byte[] data = new byte[24];
        final OtrInputStream in = new OtrInputStream(data);
        assertArrayEquals(data, in.readNonce());
    }

    @Test
    public void testReadNonceGenerated() throws ProtocolException {
        final byte[] data = new byte[24];
        RANDOM.nextBytes(data);
        final OtrInputStream in = new OtrInputStream(data);
        assertArrayEquals(data, in.readNonce());
    }

    @Test
    public void testReadNonceOversized() throws ProtocolException {
        final byte[] data = new byte[25];
        data[24] = (byte) 0xff;
        final OtrInputStream in = new OtrInputStream(data);
        final byte[] result = in.readNonce();
        assertEquals(24, result.length);
        assertTrue(allZeroBytes(result));
    }

    @Test(expected = ProtocolException.class)
    public void testReadOTR4MacMissingData() throws ProtocolException {
        final byte[] data = new byte[63];
        final OtrInputStream in = new OtrInputStream(data);
        in.readMacOTR4();
    }

    @Test
    public void testReadOTR4MacAllZero() throws ProtocolException {
        final byte[] data = new byte[64];
        final OtrInputStream in = new OtrInputStream(data);
        assertArrayEquals(data, in.readMacOTR4());
    }

    @Test
    public void testReadOTR4Mac() throws ProtocolException {
        final byte[] data = new byte[64];
        RANDOM.nextBytes(data);
        final OtrInputStream in = new OtrInputStream(data);
        assertArrayEquals(data, in.readMacOTR4());
    }

    @Test
    public void testReadOTR4MacWithSpareData() throws ProtocolException {
        final byte[] data = new byte[65];
        data[64] = (byte) 0xff;
        final OtrInputStream in = new OtrInputStream(data);
        final byte[] result = in.readMacOTR4();
        assertEquals(64, result.length);
        assertTrue(allZeroBytes(result));
    }

    @Test
    public void testReadPoint() throws OtrCryptoException, ProtocolException {
        final byte[] data;
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writePoint(keypair.getPublicKey());
            data = out.toByteArray();
        }
        final OtrInputStream in = new OtrInputStream(data);
        final Point result = in.readPoint();
        assertNotNull(result);
        assertEquals(this.keypair.getPublicKey().x(), result.x());
        assertEquals(this.keypair.getPublicKey().y(), result.y());
    }

    @Test
    public void testReadPointWithExcessData() throws OtrCryptoException, ProtocolException {
        final byte[] data;
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writePoint(keypair.getPublicKey());
            out.writeByte(RANDOM.nextInt());
            data = out.toByteArray();
        }
        final OtrInputStream in = new OtrInputStream(data);
        final Point result = in.readPoint();
        assertNotNull(result);
        assertEquals(this.keypair.getPublicKey().x(), result.x());
        assertEquals(this.keypair.getPublicKey().y(), result.y());
    }

    @Test(expected = ProtocolException.class)
    public void testReadPointShifted() throws OtrCryptoException, ProtocolException {
        final byte[] data;
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writeByte(0xff);
            out.writePoint(keypair.getPublicKey());
            data = out.toByteArray();
        }
        new OtrInputStream(data).readPoint();
    }

    @Test(expected = ProtocolException.class)
    public void testReadPointPartial() throws OtrCryptoException, ProtocolException {
        final byte[] data = new byte[60];
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.writePoint(keypair.getPublicKey());
            final byte[] full = out.toByteArray();
            System.arraycopy(full, 0, data, 0, full.length-1);
        }
        final OtrInputStream in = new OtrInputStream(data);
        final Point result = in.readPoint();
        assertNotNull(result);
        assertEquals(this.keypair.getPublicKey().x(), result.x());
        assertEquals(this.keypair.getPublicKey().y(), result.y());
    }

    @Test(expected = ProtocolException.class)
    public void testReadEdDSASignatureBytesMissing() throws ProtocolException {
        final byte[] sig = this.keypair.sign("hello world".getBytes(UTF_8));
        final byte[] data = new byte[113];
        System.arraycopy(sig, 0, data, 0, data.length);
        try (final OtrInputStream in = new OtrInputStream(data)) {
            in.readEdDSASignature();
        }
    }

    @Test
    public void testReadEdDSASignature() throws ProtocolException {
        final byte[] sig = this.keypair.sign("hello world".getBytes(UTF_8));
        final byte[] result;
        try (final OtrInputStream in = new OtrInputStream(sig)) {
            result = in.readEdDSASignature();
        }
        assertArrayEquals(sig, result);
    }

    @Test
    public void testReadEdDSASignatureExcessData() throws ProtocolException {
        final byte[] data = new byte[115];
        RANDOM.nextBytes(data);
        final byte[] sig = this.keypair.sign("hello world".getBytes(UTF_8));
        System.arraycopy(sig, 0, data, 0, sig.length);
        final byte[] result;
        try (final OtrInputStream in = new OtrInputStream(data)) {
            result = in.readEdDSASignature();
        }
        assertArrayEquals(sig, result);
    }

    @Test
    public void testReadEdDSASignatureOffset() throws ProtocolException {
        final byte[] data = new byte[115];
        data[0] = (byte) 0xff;
        final byte[] sig = this.keypair.sign("hello world".getBytes(UTF_8));
        System.arraycopy(sig, 0, data, 1, sig.length);
        final byte[] result;
        try (final OtrInputStream in = new OtrInputStream(data)) {
            result = in.readEdDSASignature();
        }
        assertFalse(Arrays.equals(sig, result));
    }
}
