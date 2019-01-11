/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smp;

import net.java.otr4j.api.TLV;
import org.junit.Test;

import static net.java.otr4j.session.smp.SmpTlvHandler.smpPayload;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
public final class SmpTlvHandlerTest {

    @Test(expected = NullPointerException.class)
    public void testSmpTlvNull() {
        smpPayload(null);
    }

    @Test
    public void testSmpTlvVerifyAllSMPTLVs() {
        assertFalse("TLV type 0", smpPayload(new TLV(0, new byte[0])));
        assertFalse("TLV type 1", smpPayload(new TLV(1, new byte[0])));
        for (int i = 2; i < 8; i++) {
            assertTrue("TLV type " + i, smpPayload(new TLV(i, new byte[0])));
        }
        for (int i = 8; i < 200; i++) {
            assertFalse("TLV type " + i, smpPayload(new TLV(i, new byte[0])));
        }
    }

}