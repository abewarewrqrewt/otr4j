package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session.OTRv;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.ZERO_VALUE;
import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;

/**
 * An OTR message that represents a fragment of an OTR-encoded message.
 */
public final class Fragment implements Message {

    /**
     * Maximum supported number of fragments.
     */
    private static final int MAX_FRAGMENTS = 65535;

    /**
     * OTRv2 fragment pattern.
     * <p>
     * Group 1: current message part index.
     * Group 2: total number of message parts.
     * Group 3: fragment content.
     */
    private static final Pattern PATTERN_V2 = Pattern.compile("^\\?OTR,(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    /**
     * OTRv3 fragment pattern.
     * <p>
     * Group 1: sender tag.
     * Group 2: receiver tag.
     * Group 3: current message part index.
     * Group 4: total number of message parts.
     * Group 5: fragment content.
     */
    private static final Pattern PATTERN_V3 = Pattern.compile("^\\?OTR\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8}),(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    /**
     * OTRv4 fragment pattern.
     * <p>
     * Group 1: message identifier.
     * Group 2: sender tag.
     * Group 3: receiver tag.
     * Group 4: current message part index.
     * Group 5: total number of message parts.
     * Group 6: fragment content.
     */
    private static final Pattern PATTERN_V4 = Pattern.compile("^\\?OTR\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8}),(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    private static final int ZERO_IDENTIFIER = 0;

    private final int version;
    private final int identifier;
    private final int sendertag;
    private final int receivertag;
    private final int index;
    private final int total;
    private final String content;

    private Fragment(final int version, final int identifier, final int sendertag, final int receivertag,
                     final int index, final int total, @Nonnull final String content) {
        this.version = version;
        this.identifier = identifier;
        this.sendertag = sendertag;
        this.receivertag = receivertag;
        this.index = index;
        this.total = total;
        this.content = requireNonNull(content);
    }

    /**
     * Parse message that is a fragment and verify its contents.
     *
     * @param message the raw message
     * @return Returns a fragment.
     * @throws ProtocolException In case of invalid fragment format, or in case of bad data in the fragment.
     */
    @Nonnull
    public static Fragment parse(@Nonnull final String message) throws ProtocolException {
        final int version;
        final int identifier;
        final int sendertag;
        final int receivertag;
        final int index;
        final int total;
        final String content;
        // Acquire data from fragment message.
        Matcher matcher;
        if ((matcher = PATTERN_V4.matcher(message)).matches()) {
            version = OTRv.FOUR;
            try {
                identifier = Integer.valueOf(matcher.group(1), 16);
                sendertag = Integer.valueOf(matcher.group(2), 16);
                receivertag = Integer.valueOf(matcher.group(3), 16);
                index = Integer.valueOf(matcher.group(4), 10);
                total = Integer.valueOf(matcher.group(5), 10);
            } catch (final NumberFormatException e) {
                throw new ProtocolException("Illegal value in version 4 fragment: " + e.getMessage());
            }
            content = matcher.group(6);
        } else if ((matcher = PATTERN_V3.matcher(message)).matches()) {
            version = OTRv.THREE;
            identifier = ZERO_IDENTIFIER;
            try {
                sendertag = Integer.valueOf(matcher.group(1), 16);
                receivertag = Integer.valueOf(matcher.group(2), 16);
                index = Integer.valueOf(matcher.group(3), 10);
                total = Integer.valueOf(matcher.group(4), 10);
            } catch (final NumberFormatException e) {
                throw new ProtocolException("Illegal value in version 3 fragment: " + e.getMessage());
            }
            content = matcher.group(5);
        } else if ((matcher = PATTERN_V2.matcher(message)).matches()) {
            version = OTRv.TWO;
            identifier = ZERO_IDENTIFIER;
            sendertag = ZERO_VALUE;
            receivertag = ZERO_VALUE;
            try {
                index = Integer.valueOf(matcher.group(1), 10);
                total = Integer.valueOf(matcher.group(2), 10);
            } catch (final NumberFormatException e) {
                throw new ProtocolException("Illegal value in version 2 fragment: " + e.getMessage());
            }
            content = matcher.group(3);
        } else {
            throw new ProtocolException("Illegal fragment format.");
        }
        // Verify data from fragment message.
        if (isValidInstanceTag(sendertag)) {
            throw new ProtocolException("Illegal sender instance tag.");
        }
        if (isValidInstanceTag(receivertag)) {
            throw new ProtocolException("Illegal receiver instance tag.");
        }
        if (index <= 0 || index > MAX_FRAGMENTS) {
            throw new ProtocolException("Illegal fragment index.");
        }
        if (total < index || total > MAX_FRAGMENTS) {
            throw new ProtocolException("Illegal fragment total.");
        }
        return new Fragment(version, identifier, sendertag, receivertag, index, total, content);
    }

    public int getVersion() {
        return version;
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getSendertag() {
        return sendertag;
    }

    public int getReceivertag() {
        return receivertag;
    }

    public int getIndex() {
        return index;
    }

    public int getTotal() {
        return total;
    }

    public String getContent() {
        return content;
    }
}
