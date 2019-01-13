/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.checkIdentity;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
public final class Ed448Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testExpectedModulus() throws Points.InvalidDataException {
        final nl.dannyvanheumen.joldilocks.Point basePoint = Points.decode(basePoint().encode());
        assertEquals(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710",
                10), basePoint.x());
        assertEquals(new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660",
                10), basePoint.y());
    }

    @Test
    public void testExpectedPrimeOrder() {
        final Scalar expected = new Scalar(new byte[] {-13, 68, 88, -85, -110, -62, 120, 35, 85, -113, -59, -115, 114, -62, 108, 33, -112, 54, -42, -82, 73, -37, 78, -60, -23, 35, -54, 124, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 63, 0});
        assertEquals(expected, primeOrder());
    }

    @Test(expected = NullPointerException.class)
    public void testContainsPointNull() {
        containsPoint(null);
    }

    @Test
    public void testContainsBasePoint() {
        containsPoint(basePoint());
    }

    @Test(expected = NullPointerException.class)
    public void testCheckIdentityNull() {
        checkIdentity(null);
    }

    @Test
    public void testCheckIdentityIdentityPoint() throws ValidationException {
        final byte[] identity = new byte[57];
        identity[0] = 1;
        assertTrue(checkIdentity(Point.decodePoint(identity)));
    }

    @Test
    public void testCheckIdentityRandomPoint() {
        final byte[] data = new byte[57];
        final Point randomPoint = new Point(randomBytes(RANDOM, data));
        assumeFalse(Arrays.equals(data, new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
        assertFalse(checkIdentity(randomPoint));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCheckIdentityPointTooSmall() {
        final byte[] data = new byte[56];
        checkIdentity(new Point(data));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCheckIdentityPointTooLarge() {
        final byte[] data = new byte[58];
        checkIdentity(new Point(data));
    }

    @Test(expected = NullPointerException.class)
    public void testMultiplyByBaseNull() {
        multiplyByBase(null);
    }

    @Test
    public void testMultiplyByBaseOne() {
        final Point point = multiplyByBase(Scalars.one());
        assertNotNull(point);
    }

    @Test
    public void testVerifyQ() {
        assertTrue(checkIdentity(multiplyByBase(primeOrder())));
    }

    @Test
    public void testContainsDoubleBasePoint() {
        assertTrue(containsPoint(multiplyByBase(Scalar.fromBigInteger(BigInteger.valueOf(2L)))));
    }

    @Test
    public void testContainsArbitraryPoint() {
        final Point p = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        assertTrue(containsPoint(p));
    }
}