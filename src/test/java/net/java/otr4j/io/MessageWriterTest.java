/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.MessageWriter.writeMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MessageWriterTest {

    @Test
    public void testPlaintextMessageNoNullMangling() {
        final String data = "This is a test with \0 null \0 values.";
        final PlainTextMessage m = new PlainTextMessage(new HashSet<>(Arrays.asList(Version.TWO, Version.THREE)), data);
        assertTrue(writeMessage(m).startsWith("This is a test with \0 null \0 values."));
    }

    @Test
    public void testQueryHeaderEmpty() {
        // Verify that we do not send the "bizarre claim" (as documented by otr spec) of willingness to speak otr but we accept not a single version.
        final QueryMessage msg = new QueryMessage(Collections.<Integer>emptySet());
        assertEquals("", writeMessage(msg));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testCorrectQueryHeaderV1() {
        final QueryMessage msg = new QueryMessage(Collections.singleton(1));
        assertEquals("", writeMessage(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2() {
        final QueryMessage msg = new QueryMessage(Collections.singleton(Session.Version.TWO));
        assertEquals("?OTRv2?", writeMessage(msg));
    }

    @Test
    public void testCorrectQueryHeaderV3() {
        final QueryMessage msg = new QueryMessage(Collections.singleton(Session.Version.THREE));
        assertEquals("?OTRv3?", writeMessage(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2AndV3() {
        final QueryMessage msg = new QueryMessage(new HashSet<>(Arrays.asList(Version.TWO, Session.Version.THREE)));
        assertEquals("?OTRv23?", writeMessage(msg));
    }

    @Test
    public void testWhitespaceTagsNoVersions() {
        final PlainTextMessage m = new PlainTextMessage(Collections.<Integer>emptySet(), "Hello");
        assertEquals("Hello", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsAllVersions() {
        final HashSet<Integer> versions = new HashSet<>();
        versions.add(Session.Version.TWO);
        versions.add(Version.THREE);
        versions.add(Version.FOUR);
        final PlainTextMessage m = new PlainTextMessage(versions, "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsVersion2Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(Version.TWO), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t ", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsVersion3Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(Version.THREE), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t\t", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsVersion4Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(Version.FOUR), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t \t  ", writeMessage(m));
    }

    @Test
    public void testWriteErrorMessage() {
        final ErrorMessage errorMessage = new ErrorMessage("Hello, you did something wrong, but I'm not gonna tell you what.");
        assertEquals("?OTR Error:Hello, you did something wrong, but I'm not gonna tell you what.",
                writeMessage(errorMessage));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testErrorOnWritingArbitraryMessage() {
        writeMessage(new Message() {
        });
    }

    @Test
    public void testWriteOtrEncodable() {
        final String message = writeMessage(new OtrEncodableTestMessage("Hello world!"));
        assertEquals("?OTR:" + Base64.toBase64String("Hello world!".getBytes(UTF_8)) + ".", message);
    }

    private static final class OtrEncodableTestMessage implements Message, OtrEncodable {

        private final String message;

        private OtrEncodableTestMessage(@Nonnull final String message) {
            this.message = requireNonNull(message);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeMessage(this.message);
        }
    }
}
