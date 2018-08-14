package net.java.otr4j.util;

import org.junit.Test;

import static net.java.otr4j.util.Integers.parseUnsignedInt;
import static net.java.otr4j.util.Integers.requireAtLeast;
import static net.java.otr4j.util.Integers.requireInRange;
import static org.junit.Assert.*;

@SuppressWarnings({"ResultOfMethodCallIgnored", "ConstantConditions"})
public class IntegersTest {

    @Test
    public void testAtLeastMinValue() {
        final int v = 15;
        assertEquals(v, requireAtLeast(15, v));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAtLeastBelowMinValue() {
        final int v = 15;
        requireAtLeast(16, v);
    }

    @Test
    public void testAtLeastAboveMinValue() {
        final int v = 32;
        assertEquals(32, requireAtLeast(30, v));
    }

    @Test
    public void testRequireInRange() {
        assertEquals(0, requireInRange(0, 0, 0));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireInRangeFailsImpossibleRange() {
        requireInRange(0, -1, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireInRangeFailsOutsideOfRange() {
        requireInRange(0, 1, -1);
    }

    @Test
    public void testRequireInRangeFailsInsideRange() {
        assertEquals(-5, requireInRange(-10, 9, -5));
    }

    @Test(expected = NullPointerException.class)
    public void testParseUnsignedIntNullText() {
        parseUnsignedInt(null, 10);
    }

    @Test(expected = NumberFormatException.class)
    public void testParseUnsignedIntEmptyText() {
        parseUnsignedInt("", 10);
    }

    @Test
    public void testParseUnsignedIntNegativeValue() {
        parseUnsignedInt("-10", 10);
    }

    @Test
    public void testParseUnsignedIntSmallValue() {
        assertEquals(42, parseUnsignedInt("42", 10));
    }

    @Test
    public void testParseUnsignedIntMaximumContainedIn32Bits() {
        assertEquals(-1, parseUnsignedInt("ffffffff", 16));
    }
}
