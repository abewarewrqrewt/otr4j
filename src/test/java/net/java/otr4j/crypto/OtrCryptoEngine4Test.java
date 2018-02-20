package net.java.otr4j.crypto;

import org.junit.Test;

import java.math.BigInteger;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static net.java.otr4j.crypto.OtrCryptoEngine4.FINGERPRINT_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDF_1_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDF_2_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf2;
import static nl.dannyvanheumen.joldilocks.Ed448.P;
import static nl.dannyvanheumen.joldilocks.Points.identity;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public class OtrCryptoEngine4Test {

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
        kdf1(null, 0, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullInput() {
        final byte[] dst = new byte[100];
        kdf1(dst, 0, null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf1(new byte[1], 0, input);
    }

    @Test
    public void testKdf1DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 0};
        final byte[] dst = new byte[KDF_1_LENGTH_BYTES + 1];
        kdf1(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[KDF_1_LENGTH_BYTES + 1];
        kdf1(dst, 1, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[KDF_1_LENGTH_BYTES];
        kdf1(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[KDF_1_LENGTH_BYTES];
        kdf1(dst, 1, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf2NullDestination() {
        final byte[] input = "someinput".getBytes(US_ASCII);
        kdf2(null, 0, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf2NullInput() {
        final byte[] dst = new byte[100];
        kdf2(dst, 0, null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf2DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf2(new byte[1], 0, input);
    }

    @Test
    public void testKdf2DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 82, 15, -101, -65, -70, 57, -87, 63, 52, -28, -120, 54, -82, 75, 67, 66, 103, -37, 26, 68, -8, 86, -97, -15, -117, 111, 58, 2, 82, -60, 68, 11, 0};
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES + 1];
        kdf2(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf2DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 82, 15, -101, -65, -70, 57, -87, 63, 52, -28, -120, 54, -82, 75, 67, 66, 103, -37, 26, 68, -8, 86, -97, -15, -117, 111, 58, 2, 82, -60, 68, 11};
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES + 1];
        kdf2(dst, 1, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf2() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 82, 15, -101, -65, -70, 57, -87, 63, 52, -28, -120, 54, -82, 75, 67, 66, 103, -37, 26, 68, -8, 86, -97, -15, -117, 111, 58, 2, 82, -60, 68, 11};
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES];
        kdf2(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf2WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[KDF_2_LENGTH_BYTES];
        kdf2(dst, 1, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdfNullDestination() {
        kdf(null, 0, 40, new byte[1]);
    }

    @Test(expected = NullPointerException.class)
    public void testKdfNullInput() {
        kdf(new byte[40], 0, 40, null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdfNegativeOffset() {
        kdf(new byte[40], -100, 40, new byte[10]);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdfTooLargeForDestination() {
        kdf(new byte[40], 0, 41, "helloworld".getBytes(US_ASCII));
    }

    @Test
    public void testKdf() {
        final byte[] expected = new byte[]{5, -103, -33, -123, 1, -120, -63, -109, 59, 56, -36, 116, -73, -26, -105, 43, -64, 84, 35, 79, 1, -51, 127, -98, -114, 46, -116, -60, 10, -53, 20, -99, -119, 77, -101, 61, -127, 73, -54, -2, 127, -8, -107, 38, 87, 108, 125, -122, 38, 66, 74, -125, -56, 37, 34, -44, -72, 18, 15, -50, -54, 127, 115, 25, -61, 62, -82, 87, 116, 23, 73, 113, -76, -77, 71, 11, 51, 114, 1, 77, 109, 63, -48, 25, 56, 95, -6, -48, -103, -84, 68, 72, 96, -33, -21, 60, 44, -26, -46, 98, -98, -16, 87, 10, 19, 42, 125, -78, 51, 38, -56, 37, -23, -127, 115, 95, -89, -42, 31, -54};
        final int length = 120;
        final byte[] dst = new byte[length];
        kdf(dst, 0, length, "helloworld".getBytes(US_ASCII));
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdfWithOffset() {
        final byte[] expected = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, -103, -33, -123, 1, -120, -63, -109, 59, 56, -36, 116, -73, -26, -105, 43, -64, 84, 35, 79, 1, -51, 127, -98, -114, 46, -116, -60, 10, -53, 20, -99, -119, 77, -101, 61, -127, 73, -54, -2, 127, -8, -107, 38, 87, 108, 125, -122, 38, 66, 74, -125, -56, 37, 34, -44, -72, 18, 15, -50, -54, 127, 115, 25, -61, 62, -82, 87, 116, 23, 73, 113, -76, -77, 71, 11, 51, 114, 1, 77, 109, 63, -48, 25, 56, 95, -6, -48, -103, -84, 68, 72, 96, -33, -21, 60, 44, -26, -46, 98, -98, -16, 87, 10, 19, 42, 125, -78, 51, 38};
        final int length = 110;
        final byte[] dst = new byte[length + 10];
        kdf(dst, 10, length, "helloworld".getBytes(US_ASCII));
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdfWithOffsetTooSmall() {
        final int length = 110;
        final byte[] dst = new byte[length];
        kdf(dst, 10, length, "helloworld".getBytes(US_ASCII));
    }

    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullBytes() {
        hashToScalar(null);
    }

    @Test
    public void testHashToScalar() {
        final BigInteger expected = new BigInteger("108333773018303190192353867271572301960068737188431703050860533711258012813512666371637687939410892877820478365505510629241778988407354", 10);
        assertEquals(expected, hashToScalar("helloworld".getBytes(US_ASCII)));
    }
}
