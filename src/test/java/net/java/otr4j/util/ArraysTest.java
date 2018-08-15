package net.java.otr4j.util;

import org.junit.Test;

import static net.java.otr4j.util.Arrays.contains;
import static net.java.otr4j.util.Arrays.containsEmpty;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
public final class ArraysTest {

    @Test(expected = NullPointerException.class)
    public void testContainsEmptyNullArray() {
        containsEmpty(null);
    }

    @Test
    public void testContainsEmptyEmptyArray() {
        assertFalse(containsEmpty(new Object[0]));
    }

    @Test
    public void testContainsEmptySingleCellArrayEmpty() {
        assertTrue(containsEmpty(new Object[1]));
    }

    @Test
    public void testContainsEmptySingleCellArrayFilled() {
        assertFalse(containsEmpty(new Object[]{this}));
    }

    @Test
    public void testContainsEmptyManyCellArrayFilled() {
        assertFalse(containsEmpty(new Object[]{this, this, this, this, this, this, this}));
    }

    @Test
    public void testContainsEmptyManyCellArrayAlmostFilled() {
        assertTrue(containsEmpty(new Object[]{this, this, this, this, null, this, this, this}));
    }

    @Test
    public void testContainsEmptyManyCellArrayEmpty() {
        assertTrue(containsEmpty(new Object[10]));
    }

    @Test(expected = NullPointerException.class)
    public void testContainsNullElement() {
        contains(null, new String[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testContainsNullData() {
        contains("Hello", null);
    }

    @Test
    public void testContainsEmptyData() {
        assertFalse(contains("Hello", new String[0]));
    }

    @Test
    public void testContainsSingletonStringArray() {
        assertTrue(contains("Hello", new String[]{"Hello"}));
    }

    @Test
    public void testContainsSingletonStringArrayNotPresent() {
        assertFalse(contains("Hello", new String[]{"World"}));
    }

    @Test
    public void testContainsSingletonStringArraysContainingNulls() {
        assertFalse(contains("Hello", new String[1]));
    }

    @Test
    public void testContainsManyElementsFound() {
        assertTrue(contains("Hello", new String[]{"This", "is", "some", "dude", "saying", "Hello", "to", "you", "!!!"}));
    }

    @Test
    public void testContainsManyElementsNotFound() {
        assertFalse(contains("Hello", new String[]{"This", "is", "some", "dude", "saying", "Hi", "to", "you", "!!!"}));
    }

    @Test
    public void testContainsManyElementsOnlyNulls() {
        assertFalse(contains("Hello", new String[10]));
    }
}
