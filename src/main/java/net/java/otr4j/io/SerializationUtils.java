/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;

import javax.annotation.Nonnull;
import java.io.StringWriter;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.sort;
import static net.java.otr4j.io.EncodingConstants.ERROR_PREFIX;
import static net.java.otr4j.io.EncodingConstants.HEAD;
import static net.java.otr4j.io.EncodingConstants.HEAD_ENCODED;
import static net.java.otr4j.io.EncodingConstants.HEAD_ERROR;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_Q;
import static net.java.otr4j.io.EncodingConstants.HEAD_QUERY_V;
import static net.java.otr4j.io.MessageParser.encodeVersionString;
import static org.bouncycastle.util.encoders.Base64.toBase64String;

/**
 * @author George Politis
 */
// FIXME SerializationUtils is now reduced to serializing OTR messages only. Make this into a dedicated class with suitable name.
public final class SerializationUtils {

    /**
     * Null-byte indicating end of normal message payload and start of (optional) TLV records.
     */
    private static final int TLV_DATA_START_BYTE = 0x00;

    private SerializationUtils() {
        // Utility class cannot be instantiated.
    }

    /**
     * Serialize a Message into a string-representation.
     *
     * @param m the message
     * @return Returns the string-representation of the provided message.
     */
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
                sort(versions);
                writer.write(encodeVersionString(versions));
                writer.write(HEAD_QUERY_Q);
            }
        } else if (m instanceof AbstractEncodedMessage) {
            writer.write(HEAD_ENCODED);
            final byte[] otrEncodedMessage = new OtrOutputStream().write((AbstractEncodedMessage) m).toByteArray();
            writer.write(toBase64String(otrEncodedMessage));
            writer.write(".");
        } else {
            throw new UnsupportedOperationException("Unsupported message type encountered: " + m.getClass().getName());
        }
        return writer.toString();
    }

    /**
     * Extract message contents from decrypted message bytes.
     *
     * @param messageBytes Bytes of the message (decrypted)
     * @return Returns Content instances containing both the message content
     * and any TLVs that are extracted.
     * @throws ProtocolException In case of incomplete or bad message bytes.
     */
    @Nonnull
    public static Content extractContents(@Nonnull final byte[] messageBytes) throws ProtocolException {

        // find the null TLV separator in the package, or just use the end value
        int tlvIndex = messageBytes.length;
        for (int i = 0; i < messageBytes.length; i++) {
            if (messageBytes[i] == TLV_DATA_START_BYTE) {
                tlvIndex = i;
                break;
            }
        }

        // get message body without trailing 0x00, expect UTF-8 bytes
        final String message = new String(messageBytes, 0, tlvIndex, UTF_8);

        // if the null TLV separator is somewhere in the middle, there are TLVs
        final ArrayList<TLV> tlvs = new ArrayList<>();
        tlvIndex++; // to ignore the null value that separates message from TLVs
        if (tlvIndex < messageBytes.length) {
            final byte[] tlvsb = new byte[messageBytes.length - tlvIndex];
            System.arraycopy(messageBytes, tlvIndex, tlvsb, 0, tlvsb.length);
            final OtrInputStream in = new OtrInputStream(tlvsb);
            while (in.available() > 0) {
                tlvs.add(in.readTLV());
            }
        }

        return new Content(message, tlvs);
    }

    /**
     * Content is an inner class that is used to return both message body and accompanying TLVs.
     */
    public static final class Content {
        /**
         * The plaintext (user) message content.
         */
        public final String message;
        /**
         * The TLVs embedded in the Data message.
         */
        public final List<TLV> tlvs;

        private Content(@Nonnull final String message, @Nonnull final List<TLV> tlvs) {
            this.message = Objects.requireNonNull(message);
            this.tlvs = Objects.requireNonNull(tlvs);
        }
    }
}
