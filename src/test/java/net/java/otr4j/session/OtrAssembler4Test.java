package net.java.otr4j.session;

import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class OtrAssembler4Test {

    private static final String helloWorldBase64 = toBase64String("Hello World!".getBytes(UTF_8));

    @Test
    public void testConstruction() {
        new OtrAssembler4();
    }

    @Test(expected = NullPointerException.class)
    public void testNullMessage() {
        final OtrAssembler4 assembler = new OtrAssembler4();
        assembler.accumulate(null);
    }

    @Test
    public void testEmptyMessage() {
        final String msg = "";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertSame(msg, assembler.accumulate(msg));
    }

    @Test
    public void testArbitraryMessage() {
        final String msg = "This is an arbitrary message that definitely is not fragmented.";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertSame(msg, assembler.accumulate(msg));
    }

    @Test
    public void testAssemblySingleFragment() {
        final String fragment = String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64);
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertEquals(helloWorldBase64, assembler.accumulate(fragment));
        // FIXME consider testing correct removal of completed fragments.
    }

    @Test
    public void testAssembleTwoPartMessage() {
        final String part1 = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00002," + helloWorldBase64.substring(0, 8) + ",";
        final String part2 = "?OTR|3c5b5f03|5a73a599|27e31597,00002,00002," + helloWorldBase64.substring(8) + ",";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(part1));
        assertEquals(helloWorldBase64, assembler.accumulate(part2));
    }

    @Test
    public void testAssembleSixteenPartMessage() {
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
        final OtrAssembler4 assembler = new OtrAssembler4();
        for (int i = 0; i < parts.length-1; i++) {
            assertNull(assembler.accumulate(parts[i]));
        }
        assertEquals(helloWorldBase64, assembler.accumulate(parts[parts.length-1]));
    }

    @Test
    public void testAssemblyEmptyFragment() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertEquals("", assembler.accumulate(fragment));
    }

    @Test
    public void testOTRv3FormattedFragmentIgnored() {
        final String fragment = String.format("?OTR|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64);
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertSame(fragment, assembler.accumulate(fragment));
    }

    @Test
    public void testIncompleteFragmentParsing() {
        final String source = String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64);
        final OtrAssembler4 assembler = new OtrAssembler4();
        for (int i = 0; i < source.length()-1; i++) {
            final String fragment = source.substring(0, i);
            assertSame("Failed to reject fragment: " + fragment, fragment, assembler.accumulate(fragment));
        }
        assertEquals(helloWorldBase64, assembler.accumulate(source));
    }

    @Test
    public void testFragmentationFormatLegalVariations() {
        final String[] variants = new String[]{
            "?OTR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|C5B5F03|5A73A599|27E31597,00001,00001,%s,",
            "?OTR|5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|3|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|a73a599|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|73a599|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|3a599|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|a599|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|599|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|99|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|9|27e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|7e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|e31597,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|31597,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|1597,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|597,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|97,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|7,00001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,0001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,001,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,01,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,1,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,0001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,001,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,01,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,1,%s,",
        };
        final OtrAssembler4 assembler = new OtrAssembler4();
        for (final String variant : variants) {
            final String input = String.format(variant, helloWorldBase64);
            assertEquals("Variant failed: " + variant, helloWorldBase64, assembler.accumulate(input));
        }
    }

    @Test
    public void testFragmentationFormatIllegalVariations() {
        final String[] variants = new String[]{
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s",
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,,%s,",
            "?OTR|3c5b5f03|5a73a599|27e31597,,00001,%s,",
            "?OTR|3c5b5f03|5a73a599|,00001,00001,%s,",
            "?OTR|3c5b5f03||27e31597,00001,00001,%s,",
            "?OTR||5a73a599|27e31597,00001,00001,%s,",
            "?OT|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?O|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?TR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?R|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "OTR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "TR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "R|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTRc5b5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|c5b5f035a73a599|27e31597,00001,00001,%s,",
            "?OTR|c5b5f03|5a73a59927e31597,00001,00001,%s,",
            "?OTR|c5b5f03|5a73a599|27e3159700001,00001,%s,",
            "?OTR|c5b5f03|5a73a599|27e31597,0000100001,%s,",
            "?OTR|c5b5f03|5a73a599|27e31597,00001,00001%s,",
            "?OTR|c5g5f03|5a73a599|27e31597,00001,00001,%s,",
            "?OTR|c5b5f03|5a73g599|27e31597,00001,00001,%s,",
            "?OTR|c5b5f03|5a73a599|27e315g7,00001,00001,%s,",
            "?OTR|c5b5f03|5a73a599|27e31597,00a01,00001,%s,",
            "?OTR|c5b5f03|5a73a599|27e31597,00001,000b1,%s,",
            "?OTR|c5b5f03|5a73a599|27e31597,00001,00001,%s.",
            "?OTR|c5b5f03|5a73a599|27e31597,00001,-0001,%s,",
            "?OTR|c5b5f03|5a73a599|27e31597,-0001,00001,%s,",
        };
        final OtrAssembler4 assembler = new OtrAssembler4();
        for (final String variant : variants) {
            final String input = String.format(variant, helloWorldBase64);
            assertSame("Variant failed: " + variant, input, assembler.accumulate(input));
        }
    }

    @Test
    public void testFragmentIndexZero() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,00000,00001,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
    }

    @Test
    public void testFragmentTotalZero() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00000,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
    }

    @Test
    public void testFragmentIndexLargerThanTotal() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,00002,00001,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
    }

    @Test
    public void testFragmentIndexMuchLargerThanTotal() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,11111,00001,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
    }

    @Test
    public void testFragmentIndexOverMaximum() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,65536,00001,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
    }

    @Test
    public void testFragmentTotalOverMaximum() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,00001,65536,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
    }

    @Test
    public void testAssembleTwoPartMessageDriftingTotal() {
        final String part1 = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00003," + helloWorldBase64.substring(0, 8) + ",";
        final String part2 = "?OTR|3c5b5f03|5a73a599|27e31597,00002,00002," + helloWorldBase64.substring(8) + ",";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(part1));
        assertNull(assembler.accumulate(part2));
    }

    @Test
    public void testFragmentReceivedMultipleTimesIgnoring() {
        final String fragment = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,,";
        final OtrAssembler4 assembler = new OtrAssembler4();
        assertNull(assembler.accumulate(fragment));
        assertNull(assembler.accumulate(fragment));
    }
}
