package net.java.otr4j.util;

import org.junit.Test;

import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static net.java.otr4j.util.Collections.requireMinElements;
import static net.java.otr4j.util.Collections.requireNoIllegalValues;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class CollectionsTest {

    @Test(expected = NullPointerException.class)
    public void testRequireNoIllegalValuesNullList() {
        requireNoIllegalValues(null, emptyList());
    }

    @Test
    public void testRequireNoIllegalValuesNoIllegals() {
        final List<String> list = asList("a", "b", "c");
        assertSame(list, requireNoIllegalValues(list, java.util.Collections.<String>emptyList()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireNoIllegalValuesWithIllegalValue() {
        final List<String> list = asList("a", "b", "c");
        requireNoIllegalValues(list, singletonList("a"));
    }

    @Test
    public void testRequireNoIllegalValuesNonintersectingIllegals() {
        final List<String> list = asList("a", "b", "c");
        assertSame(list, requireNoIllegalValues(list, singletonList("d")));
    }

    @Test(expected = NullPointerException.class)
    public void testRequireMinElementsNullCollection() {
        requireMinElements(0, null);
    }

    @Test
    public void testRequireMinElementsEmptyCollection() {
        final List<Object> list = emptyList();
        assertSame(list, requireMinElements(0, list));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireMinElementsBelowMinimum() {
        requireMinElements(1, emptyList());
    }

    @Test
    public void testRequireMinElementsAtMinimum() {
        final List<String> list = singletonList("a");
        assertSame(list, requireMinElements(1, list));
    }

    @Test
    public void testRequireMinElementsAboveMinimum() {
        final List<String> list = asList("a", "b");
        assertSame(list, requireMinElements(1, list));
    }
}
