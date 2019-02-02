/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Session.Version;
import org.bouncycastle.util.encoders.Base64;

import javax.annotation.Nonnull;
import java.io.StringWriter;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static net.java.otr4j.io.EncodingConstants.ERROR_PREFIX;
import static net.java.otr4j.io.EncodingConstants.HEAD;
import static net.java.otr4j.io.EncodingConstants.HEAD_ENCODED;
import static net.java.otr4j.io.EncodingConstants.HEAD_ERROR;

/**
 * Writer for various types of messages.
 */
public final class MessageWriter {

    private MessageWriter() {
        // Utility class cannot be instantiated.
    }

    /**
     * Serialize a Message into a string-representation.
     *
     * @param m the message
     * @return Returns the string-representation of the provided message.
     */
    // FIXME write tests to verify correct Base64 encoding behavior, i.e. include padding chars at the end.
    @Nonnull
    public static String writeMessage(@Nonnull final Message m) {
        final StringWriter writer = new StringWriter();
        if (m instanceof ErrorMessage) {
            writer.write(HEAD);
            writer.write(HEAD_ERROR);
            writer.write(ERROR_PREFIX);
            writer.write(((ErrorMessage) m).error);
        } else if (m instanceof PlainTextMessage) {
            final PlainTextMessage plaintxt = (PlainTextMessage) m;
            writer.write(plaintxt.getCleanText());
            writer.write(plaintxt.getTag());
        } else if (m instanceof QueryMessage) {
            final QueryMessage query = (QueryMessage) m;
            if (query.getVersions().size() == 1 && query.getVersions().contains(Version.ONE)) {
                throw new UnsupportedOperationException("OTR v1 is no longer supported. Support in the library has been removed, so the query message should not contain a version 1 entry.");
            }
            writer.write(query.getTag());
        } else if (m instanceof OtrEncodable) {
            writer.write(HEAD);
            writer.write(HEAD_ENCODED);
            // FIXME review if we can change to `Base64.toBase64String()` again? (Now that interop problem is fixed.)
            final byte[] encoded = Base64.encode(new OtrOutputStream().write((OtrEncodable) m).toByteArray());
            writer.write(new String(encoded, US_ASCII));
            writer.write(".");
        } else {
            throw new UnsupportedOperationException("Unsupported message type encountered: " + m.getClass().getName());
        }
        return writer.toString();
    }
}
