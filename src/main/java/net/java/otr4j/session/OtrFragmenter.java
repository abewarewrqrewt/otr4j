/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.LinkedList;

import static java.util.Objects.requireNonNull;

/**
 * OTR fragmenter.
 *
 * @author Danny van Heumen
 */
// TODO keep limited history of used identifiers to ensure short-term uniqueness for identifiers used during fragmentation.
final class OtrFragmenter {

    /**
     * The maximum number of fragments supported by the OTR (v3) protocol.
     */
    private static final int MAXIMUM_NUMBER_OF_FRAGMENTS = 65535;

    /**
     * The message format of an OTRv4 message fragment.
     */
    private static final String OTRV4_MESSAGE_FRAGMENT_FORMAT = "?OTR|%08x|%08x|%08x,%05d,%05d,%s,";

    /**
     * The message format of an OTRv3 message fragment.
     */
    private static final String OTRV3_MESSAGE_FRAGMENT_FORMAT = "?OTR|%08x|%08x,%05d,%05d,%s,";

    /**
     * The message format of an OTRv2 message fragment.
     */
    private static final String OTRV2_MESSAGE_FRAGMENT_FORMAT = "?OTR,%d,%d,%s,";

    /**
     * OTRv2 header size (overhead of fragmentation).
     */
    private static final int OTRV2_HEADER_SIZE = 18;

    /**
     * OTRv3 header size (overhead of fragmentation).
     */
    private static final int OTRV3_HEADER_SIZE = 36;

    /**
     * OTRv4 header size (overhead of fragmentation).
     */
    private static final int OTRV4_HEADER_SIZE = 45;

    /**
     * Secure random instance.
     */
    private final SecureRandom random;

    /**
     * Instructions on how to fragment the input message.
     */
    private final OtrEngineHost host;

    /**
     * Session ID used to request specific infrastructure message limit.
     */
    private final SessionID sessionID;

    /**
     * Constructor.
     *
     * @param host OTR engine host calling upon OTR session
     */
    OtrFragmenter(@Nonnull final SecureRandom random, @Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID) {
        this.random = requireNonNull(random);
        this.host = requireNonNull(host);
        this.sessionID = requireNonNull(sessionID);
    }

    /**
     * Calculate the number of fragments that are required for the message to be
     * sent fragmented completely.
     *
     * @param version the negotiated protocol version
     * @param message the original message
     * @return returns the number of fragments required
     * @throws ProtocolException In case fragment size is too small to store any content or when the provided policy
     *                           does not support fragmentation, for example if only OTRv1 is allowed.
     */
    int numberOfFragments(final int version, @Nonnull final String message) throws ProtocolException {
        if (version < Session.OTRv.TWO) {
            return 1;
        }
        final int fragmentSize = this.host.getMaxFragmentSize(this.sessionID);
        if (fragmentSize >= message.length()) {
            return 1;
        }
        return computeFragmentNumber(version, message, fragmentSize);
    }

    /**
     * Compute the number of fragments required.
     *
     * @param message      the original message
     * @param fragmentSize size of fragments
     * @return returns number of fragments required.
     * @throws ProtocolException if fragment size is too small.
     */
    private int computeFragmentNumber(final int version, @Nonnull final String message, final int fragmentSize)
        throws ProtocolException {
        final int overhead = computeHeaderSize(version);
        final int payloadSize = fragmentSize - overhead;
        if (payloadSize <= 0) {
            throw new ProtocolException("Fragment size too small for storing content.");
        }
        int messages = message.length() / payloadSize;
        if (message.length() % payloadSize != 0) {
            messages++;
        }
        return messages;
    }

    /**
     * Fragment the given message into pieces.
     * <p>
     * Note that the fragmenter will fragment any arbitrary piece of content into fragments. Users need to determine
     * whether or not it is according to protocol when a message is fragmented. For example, fragments may not be
     * fragmented again.
     *
     * @param version  protocol version
     * @param sender   sender instance
     * @param receiver receiver instance
     * @param message  the original message
     * @return returns an array of message fragments. The array will contain at
     * least 1 message fragment, or more if fragmentation is necessary.
     * @throws ProtocolException if the fragment size is too small or if the maximum number of fragments is exceeded.
     */
    @Nonnull
    String[] fragment(final int version, final int sender, final int receiver, @Nonnull final String message)
        throws ProtocolException {
        final int fragmentSize = this.host.getMaxFragmentSize(this.sessionID);
        return fragment(version, sender, receiver, message, fragmentSize);
    }

    /**
     * Fragment a message according to the specified instructions.
     *
     * @param version      current session's negotiated protocol version
     * @param sendertag    the sender instance tag
     * @param receivertag  the receiver instance tag
     * @param message      the message
     * @param fragmentSize the maximum fragment size
     * @return Returns the fragmented message. The array will contain at least 1
     * message fragment, or more if fragmentation is necessary.
     * @throws ProtocolException In the case when it is impossible to fragment the message according to the specified
     *                           instructions.
     */
    @Nonnull
    private String[] fragment(final int version, final int sendertag, final int receivertag,
            @Nonnull final String message, final int fragmentSize) throws ProtocolException {
        if (fragmentSize >= message.length()) {
            return new String[]{message};
        }
        final int num = computeFragmentNumber(version, message, fragmentSize);
        if (num > MAXIMUM_NUMBER_OF_FRAGMENTS) {
            throw new ProtocolException("Number of necessary fragments exceeds limit.");
        }
        final int payloadSize = fragmentSize - computeHeaderSize(version);
        final int id = this.random.nextInt();
        int previous = 0;
        final LinkedList<String> fragments = new LinkedList<>();
        while (previous < message.length()) {
            // Either get new position or position of exact message end
            final int end = Math.min(previous + payloadSize, message.length());

            final String partialContent = message.substring(previous, end);
            fragments.add(createMessageFragment(version, id, sendertag, receivertag, fragments.size(), num,
                    partialContent));

            previous = end;
        }
        return fragments.toArray(new String[0]);
    }

    /**
     * Create a message fragment.
     *
     * @param version        the protocol version to use for these fragments
     * @param id             the current message's identifier used in all created fragments (only relevant for OTRv4)
     * @param sendertag      the current message's sender tag
     * @param receivertag    the current message's receiver tag
     * @param count          the current fragment number
     * @param total          the total number of fragments
     * @param partialContent the content for this fragment
     * @return returns the full message fragment
     * @throws UnsupportedOperationException in case v1 is only allowed in policy
     */
    @Nonnull
    private String createMessageFragment(final int version, final int id, final int sendertag, final int receivertag,
            final int count, final int total, @Nonnull final String partialContent) {
        switch (version) {
        case Session.OTRv.TWO:
            return createV2MessageFragment(count, total, partialContent);
        case Session.OTRv.THREE:
            return createV3MessageFragment(sendertag, receivertag, count, total, partialContent);
        case Session.OTRv.FOUR:
            return createV4MessageFragment(id, sendertag, receivertag, count, total, partialContent);
        default:
            throw new IllegalArgumentException("Unsupported protocol version: " + version);
        }
    }

    /**
     * Create a message fragment according to the v4 message format.
     *
     * @param id             the current message's identifier
     * @param count          the current fragment number
     * @param total          the total number of fragments
     * @param partialContent the content for this fragment
     * @return returns the full message fragment
     */
    @Nonnull
    private String createV4MessageFragment(final int id, final int sendertag, final int receivertag, final int count,
            final int total, @Nonnull final String partialContent) {
        return String.format(OTRV4_MESSAGE_FRAGMENT_FORMAT, id, sendertag, receivertag, count + 1, total, partialContent);
    }

    /**
     * Create a message fragment according to the v3 message format.
     *
     * @param count          the current fragment number
     * @param total          the total number of fragments
     * @param partialContent the content for this fragment
     * @return returns the full message fragment
     */
    @Nonnull
    private String createV3MessageFragment(final int sendertag, final int receivertag, final int count, final int total,
            @Nonnull final String partialContent) {
        return String.format(OTRV3_MESSAGE_FRAGMENT_FORMAT, sendertag, receivertag, count + 1, total, partialContent);
    }

    /**
     * Create a message fragment according to the v2 message format.
     *
     * @param count          the current fragment number
     * @param total          the total number of fragments
     * @param partialContent the content for this fragment
     * @return returns the full message fragment
     */
    @Nonnull
    private String createV2MessageFragment(final int count, final int total, @Nonnull final String partialContent) {
        return String.format(OTRV2_MESSAGE_FRAGMENT_FORMAT, count + 1, total, partialContent);
    }

    /**
     * Compute size of fragmentation header size.
     *
     * @return returns size of fragment header
     * @throws UnsupportedOperationException in case v1 is only allowed in policy
     */
    private int computeHeaderSize(final int version) {
        switch (version) {
        case Session.OTRv.TWO:
            return OTRV2_HEADER_SIZE;
        case Session.OTRv.THREE:
            return OTRV3_HEADER_SIZE;
        case Session.OTRv.FOUR:
            return OTRV4_HEADER_SIZE;
        default:
            throw new UnsupportedOperationException("Unsupported protocol version: " + version);
        }
    }
}
