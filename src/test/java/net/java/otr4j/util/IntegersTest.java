package net.java.otr4j.util;

import org.junit.Test;

import static net.java.otr4j.util.Integers.requireAtLeast;
import static org.junit.Assert.*;

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
}
