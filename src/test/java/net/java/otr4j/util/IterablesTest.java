package net.java.otr4j.util;

import org.junit.Test;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static net.java.otr4j.util.Iterables.findByType;
import static org.junit.Assert.*;

@SuppressWarnings("ConstantConditions")
public final class IterablesTest {

    @Test(expected = NullPointerException.class)
    public void testFindByTypeNullIterable() {
        findByType(null, Object.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFindByTypeNullClassForEmptyList() {
        findByType(emptyList(), null);
    }

    @Test(expected = NullPointerException.class)
    public void testFindByTypeNullClass() {
        findByType(singletonList("Hello"), null);
    }

    @Test
    public void testFindExactType() {
        assertEquals("Hello", findByType(singletonList("Hello"), String.class));
    }

    @Test
    public void testFindSubType() {
        assertEquals("Hello", findByType(asList(new Object(), "Hello"), String.class));
    }
}
