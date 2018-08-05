/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class OtrCryptoExceptionTest {

    public OtrCryptoExceptionTest() {
    }

    @Test
    public void testInstantiationWithCause() {
        new OtrCryptoException("Test", new IllegalStateException());
    }

    @Test
    public void testInstantiationWithoutCause() {
        new OtrCryptoException("Test", null);
    }

    @Test
    public void testInstantiationWithMessage() {
        new OtrCryptoException("Hello world failed validation!");
    }
}
