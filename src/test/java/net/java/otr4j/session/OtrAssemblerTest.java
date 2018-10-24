/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.Fragment;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.io.MessageParser.parse;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * Tests for OTR Assembler.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public final class OtrAssemblerTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private String helloWorldBase64 = toBase64String("Hello World!".getBytes(UTF_8));

    @Test
    public void testAssembleSinglePartMessage() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final Fragment data = (Fragment) parse(String.format("?OTR|ff123456|%08x,00001,00001,test,", tag.getValue()));
        final OtrAssembler ass = new OtrAssembler();
        assertEquals("test", ass.accumulate(data));
    }

    @Test
    public void testAssembleTwoPartMessage() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final OtrAssembler ass = new OtrAssembler();
        assertNull(ass.accumulate((Fragment) parse(String.format("?OTR|ff123456|%08x,00001,00002,abcdef,", tag.getValue()))));
        assertEquals("abcdeffedcba", ass.accumulate((Fragment) parse(
            String.format("?OTR|ff123456|%08x,00002,00002,fedcba,", tag.getValue()))));
    }

    @Test
    public void testAssembleFourPartMessage() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final OtrAssembler ass = new OtrAssembler();
        assertNull(ass.accumulate((Fragment) parse(String.format("?OTR|ff123456|%08x,00001,00004,a,", tag.getValue()))));
        assertNull(ass.accumulate((Fragment) parse(String.format("?OTR|ff123456|%08x,00002,00004,b,", tag.getValue()))));
        assertNull(ass.accumulate((Fragment) parse(String.format("?OTR|ff123456|%08x,00003,00004,c,", tag.getValue()))));
        assertEquals("abcd", ass.accumulate((Fragment) parse(String.format("?OTR|ff123456|%08x,00004,00004,d,", tag.getValue()))));
    }

    @Test
    public void testConstruction() {
        new OtrAssembler();
    }

    @Test(expected = NullPointerException.class)
    public void testNullMessage() throws ProtocolException {
        final OtrAssembler assembler = new OtrAssembler();
        assembler.accumulate(null);
    }

    @Test
    public void testAssemblySingleFragment() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Fragment fragment = (Fragment) parse(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64));
        final OtrAssembler assembler = new OtrAssembler();
        assertEquals(helloWorldBase64, assembler.accumulate(fragment));
        // FIXME consider testing correct removal of completed fragments.
    }

    @Test
    public void testAssembleTwoPartMessageOTRv4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Fragment part1 = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002," + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00002,00002," + helloWorldBase64.substring(8) + ",");
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate(part1));
        assertEquals(helloWorldBase64, assembler.accumulate(part2));
    }

    // FIXME add tests for parsing randomly shuffled fragments to mimick out-of-order behavior.
    @Test
    public void testAssembleSixteenPartMessage() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final String[] parts = new String[]{
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,00016,S,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00002,00016,G,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00003,00016,V,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00004,00016,s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00005,00016,b,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00006,00016,G,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00007,00016,8,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00008,00016,g,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00009,00016,V,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00010,00016,2,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00011,00016,9,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00012,00016,y,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00013,00016,b,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00014,00016,G,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00015,00016,Q,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00016,00016,h,",
        };
        final OtrAssembler assembler = new OtrAssembler();
        for (int i = 0; i < parts.length-1; i++) {
            assertNull(assembler.accumulate((Fragment) parse(parts[i])));
        }
        assertEquals(helloWorldBase64, assembler.accumulate((Fragment) parse(parts[parts.length-1])));
    }

    @Test
    public void testAssemblyEmptyFragment() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Fragment fragment = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,,");
        final OtrAssembler assembler = new OtrAssembler();
        assertEquals("", assembler.accumulate(fragment));
    }

    @Test(expected = ProtocolException.class)
    public void testAssembleTwoPartMessageDriftingTotalDown() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Fragment part1 = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00001,00003," + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00002,00002," + helloWorldBase64.substring(8) + ",");
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate(part1));
        assembler.accumulate(part2);
    }

    @Test(expected = ProtocolException.class)
    public void testAssembleTwoPartMessageDriftingTotalUp() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Fragment part1 = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002," + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00002,00003," + helloWorldBase64.substring(8) + ",");
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate(part1));
        assembler.accumulate(part2);
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentReceivedMultipleTimesIgnoring() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Fragment fragment = (Fragment) parse("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,,");
        final OtrAssembler assembler = new OtrAssembler();
        try {
            assertNull(assembler.accumulate(fragment));
        } catch (ProtocolException e) {
            fail("Did not expect to fail sending message the first time.");
        }
        assembler.accumulate(fragment);
    }
}
