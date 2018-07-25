/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.SignatureX;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.nio.charset.Charset;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static net.java.otr4j.io.EncodingConstants.ERROR_PREFIX;
import static net.java.otr4j.io.EncodingConstants.HEAD;
import static net.java.otr4j.io.EncodingConstants.HEAD_ENCODED;
import static net.java.otr4j.io.EncodingConstants.HEAD_ERROR;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_Q;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_V;
import static net.java.otr4j.io.messages.EncodedMessageParser.read;
import static org.bouncycastle.util.encoders.Base64.decode;
import static org.bouncycastle.util.encoders.Base64.toBase64String;

/**
 * @author George Politis
 */
public final class SerializationUtils {

    private static final Logger LOGGER = Logger.getLogger(SerializationUtils.class.getName());

    /**
     * Charset for base64-encoded content.
     */
    public static final Charset ASCII = Charset.forName("US-ASCII");

    /**
     * Charset for message content according to OTR spec.
     */
    public static final Charset UTF8 = Charset.forName("UTF-8");

    /**
     * Index of numbers such that we can easily translate from number character
     * to integer value. We use this index as we can use this also as an index
     * of valid number characters. This avoids having to do code-table-dependent
     * checks such as c &gt;= '0' and c &lt;= '9'.
     */
    private static final String NUMBERINDEX = "0123456789";

    /**
     * Index for hexadecimal symbols.
     */
    private static final char HEX_ENCODER[] = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /**
     * Index for decoding hexadecimal values.
     */
    private static final String HEX_DECODER = "0123456789ABCDEF";

    /**
     * PATTERN_WHITESPACE recognizes OTR v1, v2, v3 and v4 whitespace tags. We will continue to recognize OTR v1
     * whitespace tag for compatibility purposes and to avoid bad interpretation.
     */
    // TODO whitespace detection is lacking, there is no guarantee that whitespace tags for OTR versions will be found in this predefined order.
    private static final Pattern PATTERN_WHITESPACE = Pattern
            .compile(" \\t  \\t\\t\\t\\t \\t \\t \\t  ( \\t \\t  \\t )?(  \\t\\t  \\t )?(  \\t\\t  \\t\\t)?(  \\t\\t \\t  )?");

    private SerializationUtils() {
        // Utility class cannot be instantiated.
    }

    // Mysterious X IO.
    @Nonnull
    public static SignatureX toMysteriousX(@Nonnull final byte[] b) throws IOException, OtrCryptoException,
        UnsupportedTypeException, UnsupportedLengthException {
        try (ByteArrayInputStream in = new ByteArrayInputStream(b); OtrInputStream ois = new OtrInputStream(in)) {
            return ois.readMysteriousX();
        }
    }

    // Basic IO.
    @Nonnull
    public static byte[] writeData(@Nonnull final byte[] b) {
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writeData(b);
            return out.toByteArray();
        }
    }

    // BigInteger IO.
    @Nonnull
    public static byte[] writeMpi(@Nonnull final BigInteger bigInt) {
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writeBigInt(bigInt);
            return out.toByteArray();
        }
    }

    @Nonnull
    public static BigInteger readMpi(@Nonnull final byte[] b) throws IOException, UnsupportedLengthException {
        try (ByteArrayInputStream in = new ByteArrayInputStream(b); OtrInputStream ois = new OtrInputStream(in)) {
            return ois.readBigInt();
        }
    }

    // Public Key IO.
    @Nonnull
    public static byte[] writePublicKey(@Nonnull final DSAPublicKey pubKey) {
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writePublicKey(pubKey);
            return out.toByteArray();
        }
    }

    // Message IO.
    @Nonnull
    public static String toString(@Nonnull final Message m) {
        final StringWriter writer = new StringWriter();
        if (!(m instanceof PlainTextMessage) && !(m instanceof QueryMessage)) {
            // We avoid writing the header until we know for sure we need it. We
            // know for sure that plaintext messages do not need it. We may not
            // need it for a query message if the versions list is empty.
            writer.write(HEAD);
        }

        if (m instanceof ErrorMessage) {
            writer.write(HEAD_ERROR);
            writer.write(ERROR_PREFIX);
            writer.write(((ErrorMessage) m).error);
        } else if (m instanceof PlainTextMessage) {
            final PlainTextMessage plaintxt = (PlainTextMessage) m;
            writer.write(plaintxt.getCleanText());
            if (!plaintxt.getVersions().isEmpty()) {
                writer.write(" \t  \t\t\t\t \t \t \t  ");
                for (final int version : plaintxt.getVersions()) {
                    if (version == OTRv.TWO) {
                        writer.write("  \t\t  \t ");
                    }
                    if (version == OTRv.THREE) {
                        writer.write("  \t\t  \t\t");
                    }
                    if (version == OTRv.FOUR) {
                        writer.write("  \t\t \t  ");
                    }
                }
            }
        } else if (m instanceof QueryMessage) {
            final QueryMessage query = (QueryMessage) m;
            if (query.getVersions().size() == 1 && query.getVersions().contains(1)) {
                throw new UnsupportedOperationException("OTR v1 is no longer supported. Support in the library has been removed, so the query message should not contain a version 1 entry.");
            }
            if (query.getVersions().size() > 0) {
                writer.write(HEAD);
                writer.write(HEAD_QUERY_V);
                final ArrayList<Integer> versions = new ArrayList<>(query.getVersions());
                Collections.sort(versions);
                for (final int version : versions) {
                    // As all versions still present in the versions list
                    // could potentially be filtered out, we may end up with
                    // a query string "?OTRv?". Although this is strange it
                    // is documented by OTR and is considered a strange but
                    // valid use case.
                    if (version <= 1 || version > 9) {
                        LOGGER.log(Level.WARNING, "Encountered illegal OTR version: {0}. Versions 1 and lower and over 9 are not supported. This version will be skipped. If you see this message, there is likely a bug in otr4j.", version);
                        continue;
                    }
                    writer.write(NUMBERINDEX.charAt(version));
                }
                writer.write(HEAD_QUERY_Q);
            }
        } else if (m instanceof AbstractEncodedMessage) {
            writer.write(HEAD_ENCODED);
            try (OtrOutputStream out = new OtrOutputStream()) {
                out.write((AbstractEncodedMessage) m);
                writer.write(toBase64String(out.toByteArray()));
            }
            writer.write(".");
        } else {
            throw new UnsupportedOperationException("Unsupported message type encountered: " + m.getClass().getName());
        }
        return writer.toString();
    }

    /**
     * Parses an encoded OTR string into an instance of {@link Message}.
     *
     * @param s
     *            the string to parse
     * @return the parsed message
     * @throws IOException
     *             error parsing the string to a message, either format mismatch
     *             or real IO error
     * @throws net.java.otr4j.crypto.OtrCryptoException error of cryptographic nature
     */
    // TODO remove OTRv2 support in due time
    @Nullable
    public static Message toMessage(@Nonnull final String s) throws OtrCryptoException, IOException, UnsupportedLengthException {
        if (s.length() == 0) {
            return null;
        }

        final int idxHead = s.indexOf(HEAD);
        if (idxHead > -1) {
            // Message **contains** the string "?OTR". Check to see if it is an error message, a query message or a data
            // message.

            final char contentType = s.charAt(idxHead + HEAD.length());
            final int idxHeaderBody = idxHead + HEAD.length() + 1;
            final String content = s.substring(idxHeaderBody);

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
                    // FIXME Consider if we even want to return a QueryMessage here. The only accepted versions are unsupported version, hence we can just as well return null.
                    return new QueryMessage("", Collections.<Integer>emptySet());
                }
                final Set<Integer> versions = parseVersionString(versionString);
                return new QueryMessage(s.substring(idxHead, s.indexOf('?', idxHeaderBody) + 1), versions);
            } else if (idxHead == 0 && contentType == HEAD_ENCODED) {
                // Data message found.

                if (content.charAt(content.length() - 1) != '.') {
                    throw new ProtocolException("Invalid end to OTR encoded message.");
                }

                /*
                 * BC 1.48 added a check to throw an exception if a non-base64 character is encountered.
                 * An OTR message consists of ?OTR:AbcDefFe. (note the terminating point).
                 * Otr4j doesn't strip this point before passing the content to the base64 decoder.
                 * So in order to decode the content string we have to get rid of the '.' first.
                 */
                final ByteArrayInputStream bin = new ByteArrayInputStream(
                    decode(content.substring(0, content.length() - 1).getBytes(ASCII)));
                try (OtrInputStream otr = new OtrInputStream(bin)) {
                    return read(otr);
                }
            }
        }

        // Try to detect whitespace tag.
        final Matcher matcher = PATTERN_WHITESPACE.matcher(s);

        boolean v2 = false;
        boolean v3 = false;
        boolean v4 = false;
        while (matcher.find()) {
            // Ignore group 1 (OTRv1 tag) as V1 is not supported anymore.
            if (!v2 && matcher.start(2) > -1) {
                v2 = true;
            }
            if (!v3 && matcher.start(3) > -1) {
                v3 = true;
            }
            if (!v4 && matcher.start(4) > -1) {
                v4 = true;
            }
            if (v2 && v3 && v4) {
                break;
            }
        }

        final String cleanText = matcher.replaceAll("");
        final HashSet<Integer> versions = new HashSet<>();
        if (v2) {
            versions.add(OTRv.TWO);
        }
        if (v3) {
            versions.add(OTRv.THREE);
        }
        if (v4) {
            versions.add(OTRv.FOUR);
        }
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

    @Nonnull
    public static String byteArrayToHexString(@Nonnull final byte in[]) {
        final StringBuilder out = new StringBuilder(in.length * 2);
        for (final byte b : in) {
            out.append(HEX_ENCODER[(b >>> 4) & 0x0F]);
            out.append(HEX_ENCODER[b & 0x0F]);
        }
        return out.toString();
    }

    @Nonnull
    public static byte[] hexStringToByteArray(@Nonnull String value) {
        value = value.toUpperCase(Locale.US);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int index = 0; index < value.length(); index += 2) {
            final int high = HEX_DECODER.indexOf(value.charAt(index));
            final int low = HEX_DECODER.indexOf(value.charAt(index + 1));
            out.write((high << 4) + low);
        }
        return out.toByteArray();
    }

    /**
     * Convert the {@code String} text to a {@code byte[]}, including sanitizing
     * it to make sure no corrupt characters conflict with bytes that have
     * special meaning in OTR. Mostly, this means removing NULL bytes, since
     * {@code 0x00) is used as the separator between the message and the TLVs
     * in an OTR Data Message.
     *
     * @param msg the plain text message being sent
     * @return byte[] the incoming message converted to OTR-safe bytes
     */
    @Nonnull
    public static byte[] convertTextToBytes(@Nonnull final String msg) {
        return msg.replace('\0', '?').getBytes(UTF8);
    }

    /**
     * Check whether the provided content is OTR encoded.
     *
     * @param content the content to investigate
     * @return Returns true if content is OTR encoded, or false otherwise
     */
    @CheckReturnValue
    public static boolean otrEncoded(@Nonnull final String content) {
        return content.startsWith(HEAD + HEAD_ENCODED);
    }

    /**
     * Extract message contents from decrypted message bytes.
     *
     * @param messageBytes Bytes of the message (decrypted)
     * @return Returns Content instances containing both the message content
     * and any TLVs that are extracted.
     * @throws IOException In case of incomplete or bad message bytes.
     */
    @Nonnull
    public static Content extractContents(@Nonnull final byte[] messageBytes) throws IOException {

        // find the null TLV separator in the package, or just use the end value
        int tlvIndex = messageBytes.length;
        for (int i = 0; i < messageBytes.length; i++) {
            if (messageBytes[i] == 0x00) {
                tlvIndex = i;
                break;
            }
        }

        // get message body without trailing 0x00, expect UTF-8 bytes
        final String message = new String(messageBytes, 0, tlvIndex, UTF8);

        // if the null TLV separator is somewhere in the middle, there are TLVs
        final ArrayList<TLV> tlvs = new ArrayList<>();
        tlvIndex++; // to ignore the null value that separates message from TLVs
        if (tlvIndex < messageBytes.length) {
            final byte[] tlvsb = new byte[messageBytes.length - tlvIndex];
            System.arraycopy(messageBytes, tlvIndex, tlvsb, 0, tlvsb.length);

            final ByteArrayInputStream tin = new ByteArrayInputStream(tlvsb);
            try (OtrInputStream eois = new OtrInputStream(tin)) {
                while (tin.available() > 0) {
                    final int type = eois.readShort();
                    final byte[] tdata = eois.readTlvData();
                    tlvs.add(new TLV(type, tdata));
                }
            }
        }

        return new Content(message, tlvs);
    }

    /**
     * Content is an inner class that is used to return both message body and accompanying TLVs.
     */
    public static final class Content {
        public final String message;
        public final List<TLV> tlvs;

        private Content(@Nonnull final String message, @Nonnull final List<TLV> tlvs) {
            this.message = Objects.requireNonNull(message);
            this.tlvs = Objects.requireNonNull(tlvs);
        }
    }

    /**
     * Generate the shared session state that is used in verification the session consistency. Note that this part is
     * basically only concerned with the correct serialization of provided data.
     *
     * @param senderInstanceTag   The sender instance tag.
     * @param receiverInstanceTag The receiver instance tag.
     * @param queryTag            The query message.
     * @param senderContactID     The sender's contact ID (i.e. the infrastructure's identifier such as XMPP's bare JID.)
     * @param receiverContactID   The receiver's contact ID (i.e. the infrastructure's identifier such as XMPP's bare JID.)
     * @return Returns generate Phi value.
     */
    @Nonnull
    public static byte[] generatePhi(final int senderInstanceTag, final int receiverInstanceTag,
                                     @Nonnull final String queryTag, @Nonnull final String senderContactID,
                                     @Nonnull final String receiverContactID) {
        final byte[] queryTagBytes = queryTag.getBytes(ASCII);
        final byte[] senderIDBytes = senderContactID.getBytes(UTF8);
        final byte[] receiverIDBytes = receiverContactID.getBytes(UTF8);
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writeInt(senderInstanceTag);
            out.writeInt(receiverInstanceTag);
            out.writeData(queryTagBytes);
            out.writeData(senderIDBytes);
            out.writeData(receiverIDBytes);
            return out.toByteArray();
        }
    }
}
