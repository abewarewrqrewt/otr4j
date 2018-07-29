package net.java.otr4j.io.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import org.junit.Test;

import java.net.ProtocolException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.io.messages.Fragment.parse;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class FragmentTest {

    private static final String helloWorldBase64 = toBase64String("Hello World!".getBytes(UTF_8));

    private static final String formatVersion4 = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,";

    @Test(expected = NullPointerException.class)
    public void testParseNullMessage() throws ProtocolException {
        parse(null);
    }

    @Test(expected = ProtocolException.class)
    public void testParseEmptyMessage() throws ProtocolException {
        parse("");
    }

    @Test(expected = ProtocolException.class)
    public void testParseArbitraryTextMessage() throws ProtocolException {
        parse("This is an arbitrary message that is definitely not a fragment.");
    }

    @Test
    public void testParseSingleFragmentOTRv4() throws ProtocolException {
        final Fragment fragment = parse(String.format(formatVersion4, helloWorldBase64));
        assertEquals(4, fragment.getVersion());
        assertEquals(0x3c5b5f03, fragment.getIdentifier());
        assertEquals(new InstanceTag(0x5a73a599), fragment.getSendertag());
        assertEquals(new InstanceTag(0x27e31597), fragment.getReceivertag());
        assertEquals(1, fragment.getIndex());
        assertEquals(1, fragment.getTotal());
        assertEquals(helloWorldBase64, fragment.getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv3() throws ProtocolException {
        final Fragment fragment = parse(String.format("?OTR|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(3, fragment.getVersion());
        assertEquals(0, fragment.getIdentifier());
        assertEquals(new InstanceTag(0x5a73a599), fragment.getSendertag());
        assertEquals(new InstanceTag(0x27e31597), fragment.getReceivertag());
        assertEquals(1, fragment.getIndex());
        assertEquals(1, fragment.getTotal());
        assertEquals(helloWorldBase64, fragment.getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv2() throws ProtocolException {
        final Fragment fragment = parse("?OTR,1,3,?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr,");
        assertEquals(2, fragment.getVersion());
        assertEquals(0, fragment.getIdentifier());
        assertEquals(ZERO_TAG, fragment.getSendertag());
        assertEquals(ZERO_TAG, fragment.getReceivertag());
        assertEquals(1, fragment.getIndex());
        assertEquals(3, fragment.getTotal());
        assertEquals("?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr",
            fragment.getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv4HighBitIdentifier() throws ProtocolException {
        final Fragment fragment = parse(String.format("?OTR|ffffffff|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(OTRv.FOUR, fragment.getVersion());
        assertEquals(0xffffffff, fragment.getIdentifier());
    }

    @Test
    public void testParseSingleFragmentOTRv4HighBitSenderTag() throws ProtocolException {
        final Fragment fragment = parse(String.format("?OTR|3c5b5f03|ffffffff|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(OTRv.FOUR, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getSendertag());
    }

    @Test
    public void testParseSingleFragmentOTRv4HighBitReceiverTag() throws ProtocolException {
        final Fragment fragment = parse(String.format("?OTR|3c5b5f03|5a73a599|ffffffff,00001,00001,%s,", helloWorldBase64));
        assertEquals(OTRv.FOUR, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getReceivertag());
    }

    @Test
    public void testParseSingleFragmentOTRv3HighBitSenderTag() throws ProtocolException {
        final Fragment fragment = parse(String.format("?OTR|ffffffff|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(OTRv.THREE, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getSendertag());
    }

    @Test
    public void testParseSingleFragmentOTRv3HighBitReceiverTag() throws ProtocolException {
        final Fragment fragment = parse(String.format("?OTR|5a73a599|ffffffff,00001,00001,%s,", helloWorldBase64));
        assertEquals(OTRv.THREE, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getReceivertag());
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalSenderTag() throws ProtocolException {
        parse(String.format("?OTR|3c5b5f03|00000001|27e31597,00001,00001,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalReceiverTag() throws ProtocolException {
        parse(String.format("?OTR|3c5b5f03|5a73a599|00000001,00001,00001,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalIndexZero() throws ProtocolException {
        parse(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00000,00001,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalIndexOverMaximum() throws ProtocolException {
        parse(String.format("?OTR|3c5b5f03|5a73a599|27e31597,65536,65536,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalTotalBelowIndex() throws ProtocolException {
        parse(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00000,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalTotalOverMaximum() throws ProtocolException {
        parse(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,65536,%s,", helloWorldBase64));
    }
}
