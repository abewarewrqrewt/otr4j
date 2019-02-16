/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.io.Fragment;
import org.junit.Test;
import org.mockito.internal.util.reflection.Whitebox;

import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.shuffle;
import static net.java.otr4j.io.MessageProcessor.parseMessage;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
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
    public void testAssembleSinglePartMessage() throws ProtocolException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final Fragment data = (Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00001,00001,test,", tag.getValue()));
        final OtrAssembler ass = new OtrAssembler();
        assertEquals("test", ass.accumulate(data));
    }

    @Test
    public void testAssembleTwoPartMessage() throws ProtocolException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final OtrAssembler ass = new OtrAssembler();
        assertNull(ass.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00001,00002,abcdef,", tag.getValue()))));
        assertEquals("abcdeffedcba", ass.accumulate((Fragment) parseMessage(
                String.format("?OTR|ff123456|%08x,00002,00002,fedcba,", tag.getValue()))));
    }

    @Test
    public void testAssembleFourPartMessage() throws ProtocolException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00001,00004,a,",
                tag.getValue()))));
        assertNull(assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00002,00004,b,",
                tag.getValue()))));
        assertNull(assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00003,00004,c,",
                tag.getValue()))));
        assertEquals("abcd", assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00004,00004,d,",
                tag.getValue()))));
        assertTrue(((Map<?, ?>) Whitebox.getInternalState(Whitebox.getInternalState(assembler, "inOrder"),
                "accumulations")).isEmpty());
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
    public void testAssemblySingleFragment() throws ProtocolException {
        final Fragment fragment = (Fragment) parseMessage(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                helloWorldBase64));
        final OtrAssembler assembler = new OtrAssembler();
        assertEquals(helloWorldBase64, assembler.accumulate(fragment));
        assertTrue(((Map<?, ?>) Whitebox.getInternalState(Whitebox.getInternalState(assembler, "outOfOrder"),
                "fragments")).isEmpty());
    }

    @Test
    public void testAssembleTwoPartMessageOTRv4() throws ProtocolException {
        final Fragment part1 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,"
                + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00002,00002,"
                + helloWorldBase64.substring(8) + ",");
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate(part1));
        assertEquals(helloWorldBase64, assembler.accumulate(part2));
    }

    @Test
    public void testAssembleSixteenPartMessage() throws ProtocolException {
        final String[] parts = new String[] {
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
        for (int i = 0; i < parts.length - 1; i++) {
            assertNull(assembler.accumulate((Fragment) parseMessage(parts[i])));
        }
        assertEquals(helloWorldBase64, assembler.accumulate((Fragment) parseMessage(parts[parts.length - 1])));
        assertTrue(((Map<?, ?>) Whitebox.getInternalState(Whitebox.getInternalState(assembler, "outOfOrder"),
                "fragments")).isEmpty());
    }

    @Test
    public void testAssembleSixteenPartMessageShuffled() throws ProtocolException {
        final List<String> parts = asList(
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
                "?OTR|3c5b5f03|5a73a599|27e31597,00016,00016,h,");
        shuffle(parts);
        final OtrAssembler assembler = new OtrAssembler();
        for (int i = 0; i < parts.size() - 1; i++) {
            assertNull(assembler.accumulate((Fragment) parseMessage(parts.get(i))));
        }
        assertEquals(helloWorldBase64, assembler.accumulate((Fragment) parseMessage(parts.get(parts.size() - 1))));
        assertTrue(((Map<?, ?>) Whitebox.getInternalState(Whitebox.getInternalState(assembler, "outOfOrder"),
                "fragments")).isEmpty());
    }

    @Test
    public void testAssemblyEmptyFragment() throws ProtocolException {
        final Fragment fragment = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,,");
        final OtrAssembler assembler = new OtrAssembler();
        assertEquals("", assembler.accumulate(fragment));
    }

    @Test(expected = ProtocolException.class)
    public void testAssembleTwoPartMessageDriftingTotalDown() throws ProtocolException {
        final Fragment part1 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00003,"
                + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00002,00002,"
                + helloWorldBase64.substring(8) + ",");
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate(part1));
        assembler.accumulate(part2);
    }

    @Test(expected = ProtocolException.class)
    public void testAssembleTwoPartMessageDriftingTotalUp() throws ProtocolException {
        final Fragment part1 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,"
                + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00002,00003,"
                + helloWorldBase64.substring(8) + ",");
        final OtrAssembler assembler = new OtrAssembler();
        assertNull(assembler.accumulate(part1));
        assembler.accumulate(part2);
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentReceivedMultipleTimesIgnoring() throws ProtocolException {
        final Fragment fragment = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,,");
        final OtrAssembler assembler = new OtrAssembler();
        try {
            assertNull(assembler.accumulate(fragment));
        } catch (ProtocolException e) {
            fail("Did not expect to fail sending message the first time.");
        }
        assembler.accumulate(fragment);
    }
}
