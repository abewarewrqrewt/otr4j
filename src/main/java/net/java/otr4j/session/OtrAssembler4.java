package net.java.otr4j.session;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static net.java.otr4j.util.Arrays.containsEmpty;
import static net.java.otr4j.util.Strings.join;

/**
 * Assembler for OTRv4 message fragments.
 */
// TODO introduce some kind of clean-up such that fragments list does not grow infinitely.
// FIXME is it still required to check the sender tag before accepting?
final class OtrAssembler4 {

    private static final int MAX_FRAGMENTS = 65535;

    /**
     * OTRv4 fragment pattern.
     *
     * Group 1: message identifier.
     * Group 2: sender tag.
     * Group 3: receiver tag.
     * Group 4: current message part counter.
     * Group 5: total number of message parts.
     * Group 6: message fragment.
     */
    // FIXME verify pattern completeness: capital, small letters, whitespaces, prefixed 0 or not, values with length < 8 (or max), null (?), ...
    private final Pattern PATTERN = Pattern.compile("^\\?OTR\\|([0-9abcdefABCDEF]{8})\\|([0-9abcdefABCDEF]{8})\\|([0-9abcdefABCDEF]{8}),(\\d{5}),(\\d{5}),([a-zA-Z0-9+/=?:.]+),$");

    private final HashMap<Integer, String[]> fragments = new HashMap<>();

    OtrAssembler4() {
        // No further preparation needed.
    }

    // FIXME sanity-check input values because user input and to prevent allocating huge amounts of memory.
    // FIXME write unit tests for cases: incorrect format, bad data, data causing huge allocations, many different ids, incorrect indexes (too high, too low), incorrect totals, differing totals, nulls(?), ...
    @Nullable
    String assemble(@Nonnull final String message) {
        final Matcher pattern = PATTERN.matcher(message);
        if (!pattern.matches()) {
            return message;
        }
        final int id = Integer.valueOf(pattern.group(1), 16);
        final int senderTag = Integer.valueOf(pattern.group(2), 16);
        final int receiverTag = Integer.valueOf(pattern.group(3), 16);
        final int index = Integer.valueOf(pattern.group(4), 10);
        // FIXME verify index is in expected range 0 < index <= MAX_FRAGMENTS.
        final int total = Integer.valueOf(pattern.group(5), 10);
        // FIXME verify total <= MAX_FRAGMENTS
        // FIXME verify index is in expected range index <= total
        final String partial = pattern.group(6);
        String[] parts = fragments.get(id);
        if (parts == null) {
            parts = new String[total];
            fragments.put(id, parts);
        }
        // FIXME do we need to sanity-check the sender tag and/or receiver tag before assuming that parts belong together?
        // FIXME handle case where total is different from pre-allocated array size.
        // FIXME how to handle case where partial data was already stored at this index?
        // FIXME do sanity check on 'total' and 'index' values before using them to allocate memory and access array content.
        parts[index-1] = partial;
        if (containsEmpty(parts)) {
            // Not all message parts are present. Return null and wait for next message part before continuing.
            return null;
        }
        fragments.remove(id);
        return join(parts);
    }
}
