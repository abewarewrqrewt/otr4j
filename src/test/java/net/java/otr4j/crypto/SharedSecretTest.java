/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import java.nio.ByteBuffer;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

/**
 * This set of tests is written based on the calculation of SharedSecret's
 * logic. Therefore these tests cannot be used to prove that SharedSecret
 * operates correctly under all circumstances. However, it can be used to prove
 * that the calculations of SharedSecret do not change over time.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class SharedSecretTest {

    private static final byte[] MY_SHARED_BYTES = new byte[] {'o', 't', 'r'};

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testNullSharedSecret() {
        new SharedSecret(null);
    }

    @Test
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testSharedSecretConstruction() {
        new SharedSecret(MY_SHARED_BYTES);
    }

    @Test
    public void testSsid() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-55, 101, -46, 79, 13, 108, -14, 117},
                s.ssid());
    }

    @Test
    public void testC() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-27, -30, -56, 57, -23, -12, -12, -30, 101,
                43, 106, 41, 96, -23, 48, 15}, s.c());
    }

    @Test
    public void testCPrime() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-57, 42, 12, 25, -21, -99, 75, 58, -9, 113,
                87, 42, 44, 77, 30, 24}, s.cp());
    }

    @Test
    public void testM1() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-99, -106, 97, -11, 23, 35, -54, 108, 23,
                31, 16, 119, -77, -94, 30, 84, -8, -53, 81, -38, 67, 66, 35, -107,
                -113, -116, 24, 7, -70, 78, -42, 14}, s.m1());
    }

    @Test
    public void testM1Prime() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-78, -61, -71, 36, 9, -57, 49, -20, 32, 77,
                -111, -7, -115, -113, -6, -82, -79, -61, -13, -45, -112, 63, 92,
                -31, 99, 12, 43, -121, -101, 86, 31, -22}, s.m1p());
    }

    @Test
    public void testM2() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {34, 33, -19, -39, -31, 44, 15, 54, -10, 71,
                33, -35, 46, -46, -24, -105, 23, -122, -62, 72, 76, -103, 123, 1,
                -28, 45, -88, -2, -5, 101, -18, 87}, s.m2());
    }

    @Test
    public void testM2Prime() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-48, 82, 14, -64, -65, -109, -81, -122,
                121, 120, -67, 6, -32, -37, -31, 95, 28, 50, -94, 21, 74, -28, 99,
                -77, -48, -13, 4, 62, -20, -31, -110, 0}, s.m2p());
    }

    @Test
    public void testExtraSymmetricKey() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-19, 90, -108, -38, 119, 18, 108, -77, 4,
                121, -121, -2, -83, 13, -90, -21, 33, -17, -25, 120, 48, -88, -30,
                -24, 116, 93, 14, 65, 100, -12, -54, 107}, s.extraSymmetricKey());
    }

    @Test
    public void testSecBytesCleared() {
        final SharedSecret s = new SharedSecret(MY_SHARED_BYTES);
        assertArrayEquals(new byte[] {-27, -30, -56, 57, -23, -12, -12, -30, 101,
                43, 106, 41, 96, -23, 48, 15}, s.c());
        s.close();
        final ByteBuffer expectedBuffer = ByteBuffer.wrap(
                OtrCryptoEngine.sha256Hash(new byte[] {1}, new byte[MY_SHARED_BYTES.length + 4]));
        final byte[] expectedC = new byte[16];
        expectedBuffer.get(expectedC);
        assertArrayEquals(expectedC, s.c());
        final byte[] expectedCprime = new byte[16];
        expectedBuffer.position(16);
        expectedBuffer.get(expectedCprime);
        assertArrayEquals(expectedCprime, s.cp());
    }
}
