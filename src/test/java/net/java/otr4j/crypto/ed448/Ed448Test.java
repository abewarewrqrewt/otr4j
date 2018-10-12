package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import java.math.BigInteger;

import static java.math.BigInteger.ONE;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings( {"ConstantConditions", "ResultOfMethodCallIgnored"})
public final class Ed448Test {

    @Test
    public void testExpectedModulus() {
        final Point basePoint = basePoint();
        assertEquals(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710",
                10), basePoint.p.x());
        assertEquals(new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660",
                10), basePoint.p.y());
    }

    @Test
    public void testExpectedPrimeOrder() {
        assertEquals(new BigInteger("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
                16), primeOrder());
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