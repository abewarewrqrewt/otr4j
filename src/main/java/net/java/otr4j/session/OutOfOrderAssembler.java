package net.java.otr4j.session;

import net.java.otr4j.io.messages.Fragment;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.logging.Logger;

/**
 * Assembler for OTRv4 (out-of-order) message fragments.
 */
// TODO introduce some kind of clean-up such that fragments list does not grow infinitely.
// TODO consider doing some fuzzing for this user input, if we can find a decent fuzzing library.
// TODO consider if needed to keep track of recently completed fragments in case another message arrives?
// FIXME is it still required to check the sender tag before accepting?
// FIXME still needs to be integrated with SessionImpl
// TODO consider implementing OTRv3 fragmentation in similar fashion and throw away old assembling logic
final class OutOfOrderAssembler {

    private static final Logger LOGGER = Logger.getLogger(OutOfOrderAssembler.class.getName());

    private final HashMap<Integer, String[]> fragments = new HashMap<>();

    OutOfOrderAssembler() {
        // No further preparation needed.
    }

    @Nullable
    String accumulate(@Nonnull final Fragment message) {
//        String[] parts = fragments.get(id);
//        if (parts == null) {
//            parts = new String[total];
//            fragments.put(id, parts);
//        }
//        if (total != parts.length) {
//            LOGGER.log(Level.INFO, "OTRv4 fragmentation of other party may be broken. Initial total is different from this message. Ignoring this fragment. (Original: {0}, current fragment: {1})",
//                new Object[]{parts.length, total});
//            return null;
//        }
//        if (parts[index - 1] != null) {
//            LOGGER.log(Level.INFO, "Fragment with index {0} was already present. Ignoring this fragment.", new Object[]{index});
//        }
//        // FIXME do we need to sanity-check the sender tag and/or receiver tag before assuming that parts belong together?
//        parts[index-1] = partial;
//        if (containsEmpty(parts)) {
//            // Not all message parts are present. Return null and wait for next message part before continuing.
//            return null;
//        }
//        fragments.remove(id);
//        return join(parts);
        throw new UnsupportedOperationException("In process of being rewritten.");
    }
}
