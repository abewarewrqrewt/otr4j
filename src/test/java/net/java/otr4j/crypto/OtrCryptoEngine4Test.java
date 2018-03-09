package net.java.otr4j.crypto;

import org.junit.Test;

import java.math.BigInteger;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static net.java.otr4j.crypto.OtrCryptoEngine4.FINGERPRINT_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf2;
import static nl.dannyvanheumen.joldilocks.Ed448.P;
import static nl.dannyvanheumen.joldilocks.Points.identity;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public class OtrCryptoEngine4Test {

    // This was previously a defined constant in KDF_2
    private static final int KDF_2_LENGTH_BYTES = 64;

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullDestination() {
        fingerprint(null, identity());
    }

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullPoint() {
        fingerprint(new byte[FINGERPRINT_LENGTH_BYTES], null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testFingerprintDestinationZeroSize() {
        fingerprint(new byte[0], identity());
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testFingerprintDestinationTooSmall() {
        fingerprint(new byte[55], identity());
    }

    @Test
    public void testFingerprintDestinationTooLarge() {
        final byte[] expected = new byte[]{-69, -21, 118, -79, 110, -32, -77, -4, 19, -103, -110, -55, 46, -56, 30, -71, -32, -2, 49, -100, -45, 81, -94, -49, 116, 95, 61, 12, 72, 57, 100, 112, -7, -82, -18, 111, 107, 99, 16, -94, -57, -100, -126, -114, 117, -89, 24, -10, 67, 22, -96, -57, -103, 73, -128, 31, 0};
        final byte[] dst = new byte[57];
        fingerprint(dst, P);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testFingerprint() {
        final byte[] expected = new byte[]{-69, -21, 118, -79, 110, -32, -77, -4, 19, -103, -110, -55, 46, -56, 30, -71, -32, -2, 49, -100, -45, 81, -94, -49, 116, 95, 61, 12, 72, 57, 100, 112, -7, -82, -18, 111, 107, 99, 16, -94, -57, -100, -126, -114, 117, -89, 24, -10, 67, 22, -96, -57, -103, 73, -128, 31};
        final byte[] dst = new byte[FINGERPRINT_LENGTH_BYTES];
        fingerprint(dst, P);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullDestination() {
        final byte[] input = "someinput".getBytes(US_ASCII);
        kdf1(null, 0, input, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullInput() {
        final byte[] dst = new byte[100];
        kdf1(dst, 0, null, 32);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf1(new byte[1], 0, input, 32);
    }

    @Test
    public void testKdf1DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 0};
        final byte[] dst = new byte[32 + 1];
        kdf1(dst, 0, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[32 + 1];
        kdf1(dst, 1, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[32];
        kdf1(dst, 0, input, 32);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf1(dst, 1, input, 32);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf2NullDestination() {
        final byte[] input = "someinput".getBytes(US_ASCII);
        kdf2(null, 0, input, KDF_2_LENGTH_BYTES);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf2NullInput() {
        final byte[] dst = new byte[100];
        kdf2(dst, 0, null, KDF_2_LENGTH_BYTES);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf2DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf2(new byte[1], 0, input, KDF_2_LENGTH_BYTES);
    }

    @Test
    public void testKdf2DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {5, -103, -33, -123, 1, -120, -63, -109, 59, 56, -36, 116, -73, -26, -105, 43, -64, 84, 35, 79, 1, -51, 127, -98, -114, 46, -116, -60, 10, -53, 20, -99, -119, 77, -101, 61, -127, 73, -54, -2, 127, -8, -107, 38, 87, 108, 125, -122, 38, 66, 74, -125, -56, 37, 34, -44, -72, 18, 15, -50, -54, 127, 115, 25, 0};
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES + 1];
        kdf2(dst, 0, input, KDF_2_LENGTH_BYTES);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf2DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 5, -103, -33, -123, 1, -120, -63, -109, 59, 56, -36, 116, -73, -26, -105, 43, -64, 84, 35, 79, 1, -51, 127, -98, -114, 46, -116, -60, 10, -53, 20, -99, -119, 77, -101, 61, -127, 73, -54, -2, 127, -8, -107, 38, 87, 108, 125, -122, 38, 66, 74, -125, -56, 37, 34, -44, -72, 18, 15, -50, -54, 127, 115, 25};
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES + 1];
        kdf2(dst, 1, input, KDF_2_LENGTH_BYTES);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf2() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {5, -103, -33, -123, 1, -120, -63, -109, 59, 56, -36, 116, -73, -26, -105, 43, -64, 84, 35, 79, 1, -51, 127, -98, -114, 46, -116, -60, 10, -53, 20, -99, -119, 77, -101, 61, -127, 73, -54, -2, 127, -8, -107, 38, 87, 108, 125, -122, 38, 66, 74, -125, -56, 37, 34, -44, -72, 18, 15, -50, -54, 127, 115, 25};
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES];
        kdf2(dst, 0, input, KDF_2_LENGTH_BYTES);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf2WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES];
        kdf2(dst, 1, input, KDF_2_LENGTH_BYTES);
    }
    
    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullBytes() {
        hashToScalar(null);
    }

    @Test
    public void testHashToScalar() {
        final BigInteger expected = new BigInteger("140888660286710823522416977182523334012318579212723175722386145079376311038285857705111942117343322765056189818196599612200095406328505", 10);
        assertEquals(expected, hashToScalar("helloworld".getBytes(US_ASCII)));
    }
}
