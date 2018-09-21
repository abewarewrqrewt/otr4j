package net.java.otr4j.io.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Integer.parseInt;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.ZERO_VALUE;
import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;
import static net.java.otr4j.util.Integers.parseUnsignedInt;

/**
 * An OTR message that represents a fragment of an OTR-encoded message.
 */
public final class Fragment implements Message {

    /**
     * Maximum supported number of fragments.
     */
    private static final int MAX_FRAGMENTS = 65535;

    private static final int DECIMAL_SYSTEM = 10;
    private static final int HEXADECIMAL_SYSTEM = 16;

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
    private final InstanceTag sendertag;
    private final InstanceTag receivertag;
    private final int index;
    private final int total;
    private final String content;

    private Fragment(final int version, final int identifier, @Nonnull final InstanceTag sendertag,
            @Nonnull final InstanceTag receivertag, final int index, final int total, @Nonnull final String content) {
        this.version = version;
        this.identifier = identifier;
        this.sendertag = requireNonNull(sendertag);
        this.receivertag = requireNonNull(receivertag);
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
    // TODO verify if suppressions are still valid (PMD.UselessParentheses should be fixed now ...)
    @SuppressWarnings({"PMD.AssignmentInOperand", "PMD.UselessParentheses"})
    @Nonnull
    public static Fragment parse(@Nonnull final String message) throws ProtocolException {
        final int version;
        final int identifier;
        final int sendertagValue;
        final int receivertagValue;
        final int index;
        final int total;
        final String content;
        // Acquire data from fragment message.
        Matcher matcher;
        if ((matcher = PATTERN_V4.matcher(message)).matches()) {
            version = OTRv.FOUR;
            identifier = parseUnsignedInt(matcher.group(1), HEXADECIMAL_SYSTEM);
            sendertagValue = parseUnsignedInt(matcher.group(2), HEXADECIMAL_SYSTEM);
            receivertagValue = parseUnsignedInt(matcher.group(3), HEXADECIMAL_SYSTEM);
            index = parseInt(matcher.group(4), DECIMAL_SYSTEM);
            total = parseInt(matcher.group(5), DECIMAL_SYSTEM);
            content = matcher.group(6);
        } else if ((matcher = PATTERN_V3.matcher(message)).matches()) {
            version = OTRv.THREE;
            identifier = ZERO_IDENTIFIER;
            sendertagValue = parseUnsignedInt(matcher.group(1), HEXADECIMAL_SYSTEM);
            receivertagValue = parseUnsignedInt(matcher.group(2), HEXADECIMAL_SYSTEM);
            index = parseInt(matcher.group(3), DECIMAL_SYSTEM);
            total = parseInt(matcher.group(4), DECIMAL_SYSTEM);
            content = matcher.group(5);
        } else if ((matcher = PATTERN_V2.matcher(message)).matches()) {
            version = OTRv.TWO;
            identifier = ZERO_IDENTIFIER;
            sendertagValue = ZERO_VALUE;
            receivertagValue = ZERO_VALUE;
            index = parseInt(matcher.group(1), DECIMAL_SYSTEM);
            total = parseInt(matcher.group(2), DECIMAL_SYSTEM);
            content = matcher.group(3);
        } else {
            throw new ProtocolException("Illegal fragment format.");
        }
        // Verify data from fragment message.
        if (!isValidInstanceTag(sendertagValue)) {
            throw new ProtocolException("Illegal sender instance tag: " + sendertagValue);
        }
        if (!isValidInstanceTag(receivertagValue)) {
            throw new ProtocolException("Illegal receiver instance tag: " + receivertagValue);
        }
        if (index <= 0 || index > MAX_FRAGMENTS) {
            throw new ProtocolException("Illegal fragment index: " + index);
        }
        if (total < index || total > MAX_FRAGMENTS) {
            throw new ProtocolException("Illegal fragment total: " + total);
        }
        return new Fragment(version, identifier, new InstanceTag(sendertagValue), new InstanceTag(receivertagValue),
            index, total, content);
    }

    /**
     * Get the protocol version.
     *
     * @return Returns the version.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Get the fragment identifier.
     * <p>
     * The identifier is common amongst all fragments of the same message.
     *
     * @return Returns the identifier.
     */
    public int getIdentifier() {
        return identifier;
    }

    /**
     * Get the sender instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getSendertag() {
        return sendertag;
    }

    /**
     * Get the receiver instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getReceivertag() {
        return receivertag;
    }

    /**
     * Get the message fragment index.
     *
     * @return Returns the index value.
     */
    public int getIndex() {
        return index;
    }

    /**
     * Get the message total number of fragments.
     *
     * @return Returns the total.
     */
    public int getTotal() {
        return total;
    }

    /**
     * Get the fragment content.
     *
     * @return Returns the content.
     */
    @Nonnull
    public String getContent() {
        return content;
    }
}
