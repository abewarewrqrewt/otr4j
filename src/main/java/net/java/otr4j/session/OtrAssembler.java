/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import net.java.otr4j.api.Session;
import net.java.otr4j.io.messages.Fragment;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.util.Arrays.containsEmpty;
import static net.java.otr4j.util.Strings.join;

/**
 * Support for re-assembling fragmented OTR-encoded messages.
 */
// TODO trace control flow to confirm that we can drop the sender tag from the Assembler logic.
final class OtrAssembler {

    private final InOrderAssembler inOrder = new InOrderAssembler();
    private final OutOfOrderAssembler outOfOrder = new OutOfOrderAssembler();

    /**
     * Accumulate fragments into a full OTR-encoded message.
     *
     * @param fragment a message fragment
     * @return Returns completed OTR-encoded message, or null if more fragments are needed to complete the message.
     * @throws ProtocolException In case the fragment is rejected.
     */
    @Nullable
    String accumulate(@Nonnull final Fragment fragment) throws ProtocolException {
        final int version = fragment.getVersion();
        switch (version) {
            case Session.OTRv.TWO:
            case Session.OTRv.THREE:
                return inOrder.accumulate(fragment);
            case Session.OTRv.FOUR:
                return outOfOrder.accumulate(fragment);
            default:
                throw new UnsupportedOperationException("Unsupported protocol version.");
        }
    }

    /**
     * In-order assembler, following OTRv2/OTRv3 specification.
     */
    private static final class InOrderAssembler {

        private final HashMap<Integer, Status> accumulations = new HashMap<>();

        /**
         * Appends a message fragment to the internal buffer and returns
         * the full message if msgText was no fragmented message or all
         * the fragments have been combined. Returns null, if there are
         * fragments pending or an invalid fragment was received.
         * <p>
         * A fragmented OTR message looks like this:
         * (V2) ?OTR,k,n,piece-k,
         *  or
         * (V3) ?OTR|sender_instance|receiver_instance,k,n,piece-k,
         *
         * @param fragment The message fragment to process.
         *
         * @return String with the accumulated message or
         *         null if the message was incomplete or malformed
         * @throws ProtocolException Thrown in case the message is bad in some way
         * that breaks with the expectations of the OTR protocol.
         */
        // TODO verify if in-order assembling follows spec (copied from original otr4j implementation, then modified to restructured fragment handling)
        @Nullable
        private String accumulate(@Nonnull final Fragment fragment) throws ProtocolException {
            final int id = fragment.getSendertag().getValue();
            if (fragment.getIndex() == 1) {
                // first fragment
                final Status status = new Status();
                status.current = fragment.getIndex();
                status.total = fragment.getTotal();
                status.content.append(fragment.getContent());
                this.accumulations.put(id, status);
            } else {
                // next fragment
                final Status status = this.accumulations.get(id);
                if (status == null) {
                    throw new ProtocolException("Rejecting fragment from unknown sender tag, for which we have not started collecting yet.");
                }
                if (fragment.getTotal() == status.total && fragment.getIndex() == status.current + 1) {
                    // consecutive fragment, in order
                    status.current++;
                    status.content.append(fragment.getContent());
                } else {
                    // out-of-order fragment
                    this.accumulations.remove(id);
                    throw new ProtocolException("Rejecting fragment that was received out-of-order.");
                }
            }

            if (fragment.getIndex() == fragment.getTotal()) {
                final Status status = this.accumulations.remove(id);
                return status.content.toString();
            }

            // Fragment did not result in completed message. Waiting for next fragment.
            return null;
        }

        /**
         * In-progress assembly status type.
         */
        private static final class Status {
            private int current;
            private int total;
            private final StringBuilder content = new StringBuilder();
        }
    }

    /**
     * Out-of-order assembler, following OTRv4 specification.
     */
    // TODO introduce some kind of clean-up such that fragments list does not grow infinitely. (Described in spec.)
    // TODO consider doing some fuzzing for this user input, if we can find a decent fuzzing library.
    private static final class OutOfOrderAssembler {

        private static final Logger LOGGER = Logger.getLogger(OutOfOrderAssembler.class.getName());

        private final HashMap<Integer, String[]> fragments = new HashMap<>();

        /**
         * Accumulate fragments.
         *
         * @param fragment the fragment to accumulate in the assembly
         * @return Returns null in case of incomplete message (more fragments needed) or reassembled message text in
         * case of complete reassembly.
         */
        @Nullable
        String accumulate(@Nonnull final Fragment fragment) throws ProtocolException {
            String[] parts = fragments.get(fragment.getIdentifier());
            if (parts == null) {
                parts = new String[fragment.getTotal()];
                fragments.put(fragment.getIdentifier(), parts);
            }
            if (fragment.getTotal() != parts.length) {
                LOGGER.log(Level.FINEST, "OTRv4 fragmentation of other party may be broken. Initial total is different from this message. Ignoring this fragment. (Original: {0}, current fragment: {1})",
                    new Object[]{parts.length, fragment.getTotal()});
                throw new ProtocolException("Rejecting fragment with different total value than other fragments of the same series.");
            }
            if (parts[fragment.getIndex() - 1] != null) {
                LOGGER.log(Level.FINEST, "Fragment with index {0} was already present. Ignoring this fragment.",
                    new Object[]{fragment.getIndex()});
                throw new ProtocolException("Rejecting fragment with index that is already present.");
            }
            // FIXME do we need to sanity-check the sender tag and/or receiver tag before assuming that parts belong together?
            parts[fragment.getIndex()-1] = fragment.getContent();
            if (containsEmpty(parts)) {
                // Not all message parts are present. Return null and wait for next message part before continuing.
                return null;
            }
            fragments.remove(fragment.getIdentifier());
            return join(parts);
        }
    }
}
