package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;

/**
 * BlockingSubmitter maintains multiple blocking queues such that each queue will be subject to all operations
 * performed on the BlockingSubmitter.
 *
 * This implementation IS NOT SAFE for concurrent/multi-threaded use! (It might not even be completely sound in
 * single-threaded use.)
 *
 * @param <E> The type of elements contained in the blocking queue.
 */
// FIXME write unit tests for BlockingSubmitter
public final class BlockingSubmitter<E> {

    private final ArrayList<BlockingQueue<E>> queues;

    public BlockingSubmitter() {
        this.queues = new ArrayList<>();
    }

    public boolean addQueue(@Nonnull final BlockingQueue<E> queue) {
        return this.queues.add(requireNonNull(queue));
    }

    public boolean removeQueue(@Nonnull final BlockingQueue<E> queue) {
        return this.queues.remove(requireNonNull(queue));
    }

    public boolean add(@Nonnull final E e) {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.add(e);
        }
        return true;
    }

    public boolean addAll(@Nonnull final Collection<? extends E> c) {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.addAll(c);
        }
        return true;
    }

    public boolean offer(@Nonnull final E e) {
        BlockingQueue<E> failedQueue = null;
        for (final BlockingQueue<E> queue : this.queues) {
            if (!queue.offer(e)) {
                failedQueue = queue;
                break;
            }
        }
        if (failedQueue == null) {
            return true;
        }
        // failed to add element to every queue, reverting changes
        for (final BlockingQueue<E> queue : this.queues) {
            if (queue == failedQueue) {
                break;
            }
            // NOTE: strictly speaking I cannot be sure that it will not remove another occurrence (than the most
            // recently added) from the queue. That's acceptable for now, but may bite me in the future.
            queue.remove(e);
        }
        return false;
    }

    public boolean offer(final E e, final long timeout, @Nonnull final TimeUnit unit) throws InterruptedException {
        // TODO currently not applying timeout to over-all offer method execution time
        BlockingQueue<E> failedQueue = null;
        for (final BlockingQueue<E> queue : this.queues) {
            if (!queue.offer(e, timeout, unit)) {
                failedQueue = queue;
                break;
            }
        }
        if (failedQueue == null) {
            return true;
        }
        // failed to add element to every queue, reverting changes
        for (final BlockingQueue<E> queue : this.queues) {
            if (queue == failedQueue) {
                break;
            }
            // NOTE: strictly speaking I cannot be sure that it will not remove another occurrence (than the most
            // recently added) from the queue. That's acceptable for now, but may bite me in the future.
            queue.remove(e);
        }
        return false;
    }

    public void put(@Nonnull final E e) throws InterruptedException {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.put(e);
        }
    }
}
