package net.java.otr4j.session;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static net.java.otr4j.util.Arrays.containsEmpty;
import static net.java.otr4j.util.Strings.join;

/**
 * Assembler for OTRv4 message fragments.
 */
// TODO introduce some kind of clean-up such that fragments list does not grow infinitely.
// TODO consider doing some fuzzing for this user input, if we can find a decent fuzzing library.
// TODO consider if needed to keep track of recently completed fragments in case another message arrives?
// FIXME is it still required to check the sender tag before accepting?
final class OtrAssembler4 {

    private static final Logger LOGGER = Logger.getLogger(OtrAssembler4.class.getName());

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
    private final Pattern PATTERN = Pattern.compile("^\\?OTR\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8}),(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    private final HashMap<Integer, String[]> fragments = new HashMap<>();

    OtrAssembler4() {
        // No further preparation needed.
    }

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
        if (index <= 0 || index > MAX_FRAGMENTS) {
            return null;
        }
        final int total = Integer.valueOf(pattern.group(5), 10);
        if (total < index || total > MAX_FRAGMENTS) {
            return null;
        }
        final String partial = pattern.group(6);
        String[] parts = fragments.get(id);
        if (parts == null) {
            parts = new String[total];
            fragments.put(id, parts);
        }
        if (total != parts.length) {
            LOGGER.log(Level.INFO, "OTRv4 fragmentation of other party may be broken. Initial total is different from this message. Ignoring this fragment. (Original: {0}, current fragment: {1})",
                new Object[]{parts.length, total});
            return null;
        }
        if (parts[index - 1] != null) {
            LOGGER.log(Level.INFO, "Fragment with index {0} was already present. Ignoring this fragment.", new Object[]{index});
        }
        // FIXME do we need to sanity-check the sender tag and/or receiver tag before assuming that parts belong together?
        parts[index-1] = partial;
        if (containsEmpty(parts)) {
            // Not all message parts are present. Return null and wait for next message part before continuing.
            return null;
        }
        fragments.remove(id);
        return join(parts);
    }
}
