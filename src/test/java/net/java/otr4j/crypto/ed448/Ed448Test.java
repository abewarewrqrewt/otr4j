package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;

import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.crypto.ed448.Scalar.ONE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings( {"ConstantConditions", "ResultOfMethodCallIgnored"})
public final class Ed448Test {

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
    public void testContainsPoint() {
        containsPoint(basePoint());
    }

    @Test(expected = NullPointerException.class)
    public void testMultiplyByBaseNull() {
        multiplyByBase(null);
    }

    @Test
    public void testMultiplyByBaseOne() {
        final Point point = multiplyByBase(ONE);
        assertNotNull(point);
    }
}