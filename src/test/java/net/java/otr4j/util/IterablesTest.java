/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.util;

import org.junit.Test;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static net.java.otr4j.util.Iterables.findByType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

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

    @Test
    public void testFindByTypeFound() {
        assertEquals("Hello", findByType(asList(new Object(), "Hello"), String.class, null));
    }

    @Test
    public void testFindByTypeNullDefault() {
        assertNull(findByType(asList(new Object(), new Object()), String.class, null));
    }

    @Test
    public void testFindByTypeNonNullDefault() {
        final String defaultValue = "Hello world";
        assertEquals(defaultValue, findByType(asList(new Object(), new Object()), String.class, defaultValue));
    }
}
