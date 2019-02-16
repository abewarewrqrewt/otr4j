/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
import org.bouncycastle.util.encoders.Base64;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.io.StringWriter;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Collections.sort;
import static net.java.otr4j.api.Session.Version.SUPPORTED;
import static net.java.otr4j.io.EncodingConstants.ERROR_PREFIX;
import static net.java.otr4j.io.EncodingConstants.HEAD;
import static net.java.otr4j.io.EncodingConstants.HEAD_ENCODED;
import static net.java.otr4j.io.EncodingConstants.HEAD_ERROR;
import static net.java.otr4j.io.EncodingConstants.HEAD_FRAGMENTED_V2;
import static net.java.otr4j.io.EncodingConstants.HEAD_FRAGMENTED_V3;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_Q;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_V;
import static net.java.otr4j.io.EncodingConstants.TAIL_FRAGMENTED;
import static org.bouncycastle.util.encoders.Base64.decode;

/**
 * Message processor.
 * <p>
 * The processor for the general OTR message structure. The parser processes the text representation of an OTR message
 * and returns a message instance. The writer processes object representations to generate text representations.
 */
public final class MessageProcessor {

    /**
     * Index of numbers such that we can easily translate from number character
     * to integer value. We use this index as we can use this also as an index
     * of valid number characters. This avoids having to do code-table-dependent
     * checks such as c &gt;= '0' and c &lt;= '9'.
     */
    private static final String NUMBERINDEX = "0123456789";

    /**
     * PATTERN_WHITESPACE recognizes OTR v1, v2, v3 and v4 whitespace tags. We will continue to recognize OTR v1
     * whitespace tag for compatibility purposes and to avoid bad interpretation.
     *
     * Group 1: OTRv1 whitespace tag.
     * Group 2: OTRv2 whitespace tag.
     * Group 3: OTRv3 whitespace tag.
     * Group 4: OTRv4 whitespace tag.
     */
    // TODO whitespace detection is lacking, there is no guarantee that whitespace tags for OTR versions will be found in this predefined order.
    @SuppressWarnings("RegExpRepeatedSpace")
    private static final Pattern PATTERN_WHITESPACE = Pattern
            .compile(" \\t  \\t\\t\\t\\t \\t \\t \\t  ( \\t \\t  \\t )?(  \\t\\t  \\t )?(  \\t\\t  \\t\\t)?(  \\t\\t \\t  )?");

    private MessageProcessor() {
        // No need to instantiate.
    }

    /**
     * Parse provided text in order to extract the Message instance that is represented.
     *
     * @param text the content represented as plain text
     * @return Returns the message instance of the message that the text represented.
     * @throws ProtocolException          In case of protocol violations.
     */
    @Nonnull
    public static Message parseMessage(@Nonnull final String text) throws ProtocolException {
        final int idxHead = text.indexOf(HEAD);
        if (idxHead > -1) {
            // Message **contains** the string "?OTR". Check to see if it is an error message, a query message or a data
            // message.

            final char contentType = text.charAt(idxHead + HEAD.length());
            final int idxHeaderBody = idxHead + HEAD.length() + 1;
            final String content = text.substring(idxHeaderBody);

            if (contentType == HEAD_ERROR && content.startsWith(ERROR_PREFIX)) {
                // Error tag found.
                return new ErrorMessage(content.substring(idxHead + ERROR_PREFIX.length()));
            } else if (contentType == HEAD_QUERY_V || contentType == HEAD_QUERY_Q) {
                // TODO This code assumes the closing '?' for the query string exists. This may not always be the case.
                // Query tag found.
                final String versionString;
                if (HEAD_QUERY_Q == contentType && content.length() > 0 && content.charAt(0) == 'v') {
                    // OTR v1 + ... query tag format. However, we do not active
                    // support OTRv1 anymore. Therefore the logic only supports
                    // skipping over the OTRv1 tags in order to reach OTR v2 and
                    // v3 version tags.
                    versionString = content.substring(1, content.indexOf('?'));
                } else if (HEAD_QUERY_V == contentType) {
                    // OTR v2+ query tag format.
                    versionString = content.substring(0, content.indexOf('?'));
                } else {
                    // OTR v1 ONLY query tags will be caught in this else clause and is unsupported.
                    return new QueryMessage(Collections.<Integer>emptySet());
                }
                final Set<Integer> versions = parseVersionString(versionString);
                return new QueryMessage(versions);
            } else if (otrFragmented(text)) {
                return Fragment.parse(text);
            } else if (otrEncoded(text)) {
                // TODO in case of slight errors in format, e.g. OTR-encoded message missing trailing '.', do we consider this incorrect message and return as plaintext or do we want to throw ProtocolException?
                // Data message found.
                /*
                 * BC 1.48 added a check to throw an exception if a non-base64 character is encountered.
                 * An OTR message consists of ?OTR:AbcDefFe. (note the terminating point).
                 * Otr4j doesn't strip this point before passing the content to the base64 decoder.
                 * So in order to decode the content string we have to get rid of the '.' first.
                 */
                final byte[] contentBytes = decode(content.substring(0, content.length() - 1).getBytes(US_ASCII));
                final OtrInputStream input = new OtrInputStream(contentBytes);
                final int protocolVersion = input.readShort();
                if (!SUPPORTED.contains(protocolVersion)) {
                    throw new ProtocolException("Unsupported protocol version " + protocolVersion);
                }
                final byte messageType = input.readByte();
                final InstanceTag senderInstanceTag;
                final InstanceTag receiverInstanceTag;
                if (protocolVersion == Version.THREE || protocolVersion == Version.FOUR) {
                    senderInstanceTag = input.readInstanceTag();
                    receiverInstanceTag = input.readInstanceTag();
                } else {
                    senderInstanceTag = InstanceTag.ZERO_TAG;
                    receiverInstanceTag = InstanceTag.ZERO_TAG;
                }
                return new EncodedMessage(protocolVersion, messageType, senderInstanceTag, receiverInstanceTag, input);
            }
        }

        // Try to detect whitespace tag.
        final Matcher matcher = PATTERN_WHITESPACE.matcher(text);

        final HashSet<Integer> versions = new HashSet<>();
        boolean v2 = false;
        boolean v3 = false;
        boolean v4 = false;
        while (matcher.find()) {
            // Ignore group 1 (OTRv1 tag) as V1 is not supported anymore.
            if (!v2 && matcher.start(2) > -1) {
                versions.add(Version.TWO);
                v2 = true;
            }
            if (!v3 && matcher.start(3) > -1) {
                versions.add(Version.THREE);
                v3 = true;
            }
            if (!v4 && matcher.start(4) > -1) {
                versions.add(Version.FOUR);
                v4 = true;
            }
            if (v2 && v3 && v4) {
                break;
            }
        }

        final String cleanText = matcher.replaceAll("");
        return new PlainTextMessage(versions, cleanText);
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

    /**
     * Encode an iterable containing integer version values into a ASCII-based string representation of the version numbers.
     *
     * @param versions The container containing the versions.
     * @return Returns ASCII string representation.
     */
    @Nonnull
    public static String encodeVersionString(@Nonnull final Iterable<Integer> versions) {
        final StringBuilder versionsString = new StringBuilder();
        for (final int version : versions) {
            if (version < 0 || version > 9) {
                throw new IllegalArgumentException("Negative and multi-digit version numbers are not supported.");
            }
            versionsString.append(version);
        }
        return versionsString.toString();
    }

    /**
     * Parse a string containing ASCII-encoded digits (plaintext version numbers) into a set containing integer version numbers.
     *
     * @param versionString The string representation of a sequence of numbers.
     * @return Returns set containing version ints.
     */
    @Nonnull
    public static Set<Integer> parseVersionString(@Nonnull final String versionString) {
        final TreeSet<Integer> versions = new TreeSet<>();
        for (final char c : versionString.toCharArray()) {
            final int idx = NUMBERINDEX.indexOf(c);
            if (idx > -1) {
                versions.add(idx);
            }
        }
        return versions;
    }

    /**
     * Check whether the provided content is OTR encoded.
     *
     * @param content the content to investigate
     * @return Returns true if content is OTR encoded, or false otherwise.
     */
    @CheckReturnValue
    private static boolean otrEncoded(@Nonnull final String content) {
        return content.startsWith(HEAD + HEAD_ENCODED) && content.endsWith(".");
    }

    /**
     * Check whether the provided content is OTR-fragment encoded.
     *
     * @param content the content to investigate
     * @return Returns true if content is OTR fragment, or false otherwise.
     */
    @CheckReturnValue
    private static boolean otrFragmented(@Nonnull final String content) {
        return (content.startsWith(HEAD + HEAD_FRAGMENTED_V2) || content.startsWith(HEAD + HEAD_FRAGMENTED_V3))
            && content.endsWith(String.valueOf(TAIL_FRAGMENTED));
    }
}
