/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class OtrExceptionTest {

    public OtrExceptionTest() {
    }

    @Test
    public void testInstantiationWithMessage() {
        new OtrException("Hello world, problem happened!");
    }

    @Test
    public void testInstantiationWithCause() {
        new OtrException("Something happened.", new IllegalStateException("something bad"));
    }

    @Test
    public void testAllowInstantiationWithNullCause() {
        new OtrException("Something happened.", null);
    }

    @Test
    public void testAllowInstantiationWithNullMessage() {
        new OtrException(null);
    }
}
