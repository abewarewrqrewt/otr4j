package net.java.otr4j.util;

import org.junit.Test;

import static net.java.otr4j.util.Strings.join;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class StringsTest {

    @Test(expected = NullPointerException.class)
    public void testJoinNull() {
        join(null);
    }

    @Test
    public void testJoinZeroStrings() {
        assertEquals("", join(new String[0]));
    }

    @Test
    public void testJoinSingleString() {
        assertEquals("Hello world", join(new String[]{"Hello world"}));
    }

    @Test
    public void testJoinTwoStrings() {
        assertEquals("HelloWorld", join(new String[]{"Hello", "World"}));
    }

    @Test
    public void testJoinManyStrings() {
        assertEquals("HelloWorldThisIsJohnDo", join(new String[]{"Hello", "World", "This", "Is", "John", "Do"}));
    }

    @Test
    public void testJoiningManyEmptyStrings() {
        assertEquals("", join(new String[]{"", "", "", ""}));
    }
}
