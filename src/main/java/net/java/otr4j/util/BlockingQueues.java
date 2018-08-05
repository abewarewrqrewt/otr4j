package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;

public final class BlockingQueues {

    private BlockingQueues() {
        // No need to instantiate utility class.
    }

    // FIXME write unit tests for shuffling entries in a blocking queue
    public static <T> void shuffle(@Nonnull final BlockingQueue<T> queue, @Nonnull final SecureRandom random) {
        final ArrayList<T> list = new ArrayList<>();
        queue.drainTo(list);
        java.util.Collections.shuffle(list, random);
        queue.addAll(list);
    }
}
