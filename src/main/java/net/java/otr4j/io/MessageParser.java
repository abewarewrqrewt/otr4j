package net.java.otr4j.io;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.messages.EncodedMessageParser;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.Fragment;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.US_ASCII;
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
 * Message parser.
 * <p>
 * The parser for the general OTR message structure. The parser processes the text representation of an OTR message and
 * returns a message instance.
 */
// TODO remove OTRv2 support in due time
public final class MessageParser {

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
    private static final Pattern PATTERN_WHITESPACE = Pattern
            .compile(" \\t  \\t\\t\\t\\t \\t \\t \\t  ( \\t \\t  \\t )?(  \\t\\t  \\t )?(  \\t\\t  \\t\\t)?(  \\t\\t \\t  )?");

    private MessageParser() {
        // No need to instantiate.
    }

    /**
     * Parse provided text in order to extract the Message instance that is represented.
     *
     * @param text the content represented as plain text
     * @return Returns the message instance of the message that the text represented.
     * @throws ProtocolException          In case of protocol violations.
     * @throws OtrCryptoException         In case of cryptographic violations, such as illegal values.
     * @throws UnsupportedLengthException In case we run into the limitations of the otr4j implementation.
     */
    @Nonnull
    public static Message parse(@Nonnull final String text) throws ProtocolException, OtrCryptoException, UnsupportedLengthException {
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
                    return new QueryMessage("", Collections.<Integer>emptySet());
                }
                final Set<Integer> versions = parseVersionString(versionString);
                return new QueryMessage(text.substring(idxHead, text.indexOf('?', idxHeaderBody) + 1), versions);
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
                return EncodedMessageParser.parse(new OtrInputStream(contentBytes));
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
                versions.add(Session.OTRv.TWO);
                v2 = true;
            }
            if (!v3 && matcher.start(3) > -1) {
                versions.add(Session.OTRv.THREE);
                v3 = true;
            }
            if (!v4 && matcher.start(4) > -1) {
                versions.add(Session.OTRv.FOUR);
                v4 = true;
            }
            if (v2 && v3 && v4) {
                break;
            }
        }

        final String cleanText = matcher.replaceAll("");
        // TODO below could be a bug .. we try to extract the whitespace tag, but in the process we assume that the matcher matches the text completely, while above we 'find' occurrences.
        return new PlainTextMessage(matcher.matches() ? matcher.group() : "", versions, cleanText);
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
