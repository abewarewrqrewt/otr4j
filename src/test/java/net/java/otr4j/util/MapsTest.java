package net.java.otr4j.util;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static net.java.otr4j.util.Maps.requireMinEntries;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class MapsTest {

    @Test(expected = NullPointerException.class)
    public void testRequireMinEntriesNullMap() {
        requireMinEntries(0, null);
    }

    @Test
    public void testRequireMinEntriesZero() {
        final Map<Object, Object> map = emptyMap();
        assertSame(map, requireMinEntries(0, map));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireMinEntriesBelowMinimum() {
        requireMinEntries(1, emptyMap());
    }

    @Test
    public void testRequireMinEntriesAtMinimum() {
        final Map<Integer, String> map = singletonMap(1, "abc");
        assertSame(map, requireMinEntries(1, map));
    }

    @Test
    public void testRequireMinEntriesAboveMinimum() {
        final HashMap<Integer, String> map = new HashMap<>();
        map.put(1, "abc");
        map.put(2, "def");
        assertSame(map, requireMinEntries(1, map));
    }
}
