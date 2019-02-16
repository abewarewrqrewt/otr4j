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
import java.util.ArrayList;

import static java.util.Collections.sort;
import static net.java.otr4j.io.EncodingConstants.ERROR_PREFIX;
import static net.java.otr4j.io.EncodingConstants.HEAD;
import static net.java.otr4j.io.EncodingConstants.HEAD_ENCODED;
import static net.java.otr4j.io.EncodingConstants.HEAD_ERROR;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_Q;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_V;
import static net.java.otr4j.io.MessageParser.encodeVersionString;

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
            writer.write(generateWhitespaceTag(plaintxt.getVersions()));
        } else if (m instanceof QueryMessage) {
            final QueryMessage query = (QueryMessage) m;
            if (query.getVersions().size() == 1 && query.getVersions().contains(Version.ONE)) {
                throw new UnsupportedOperationException("OTR v1 is no longer supported. Support in the library has been removed, so the query message should not contain a version 1 entry.");
            }
            final ArrayList<Integer> versions = new ArrayList<>(query.getVersions());
            sort(versions);
            writer.write(generateQueryTag(versions));
        } else if (m instanceof OtrEncodable) {
            writer.write(HEAD);
            writer.write(HEAD_ENCODED);
            writer.write(Base64.toBase64String(new OtrOutputStream().write((OtrEncodable) m).toByteArray()));
            writer.write(".");
        } else {
            throw new UnsupportedOperationException("Unsupported message type encountered: " + m.getClass().getName());
        }
        return writer.toString();
    }

    @Nonnull
    private static String generateWhitespaceTag(@Nonnull final Iterable<Integer> versions) {
        final StringBuilder builder = new StringBuilder(40);
        for (final int version : versions) {
            if (version == Version.TWO) {
                builder.append("  \t\t  \t ");
            }
            if (version == Version.THREE) {
                builder.append("  \t\t  \t\t");
            }
            if (version == Version.FOUR) {
                builder.append("  \t\t \t  ");
            }
        }
        return builder.length() == 0 ? "" : " \t  \t\t\t\t \t \t \t  " + builder.toString();
    }

    @Nonnull
    private static String generateQueryTag(@Nonnull final Iterable<Integer> versions) {
        final String versionsString = encodeVersionString(versions);
        return versionsString.length() == 0 ? "" : HEAD + HEAD_QUERY_V + versionsString + HEAD_QUERY_Q;
    }
}
