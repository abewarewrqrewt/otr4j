package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.lang.Math.min;
import static java.util.Objects.requireNonNull;

/**
 * Multi-BlockingQueue maintains multiple blocking queues such that each queue will be subject to all operations
 * performed on the multi-BlockingQueue.
 *
 * This implementation IS NOT SAFE for concurrent/multi-threaded use! (It might not even be completely sound in
 * single-threaded use.)
 *
 * @param <E> The type of elements contained in the blocking queue.
 */
// FIXME write unit tests for multi-BlockingQueue
// TODO consider making this a specialized class that simply offers only add/offer/put methods.
public final class SubmittingMultiBlockingQueue<E> implements BlockingQueue<E> {

    private final ArrayList<BlockingQueue<E>> queues;

    public SubmittingMultiBlockingQueue(@Nonnull final Collection<BlockingQueue<E>> queues) {
        this.queues = new ArrayList<>(queues);
    }

    public boolean addBlockingQueue(@Nonnull final BlockingQueue<E> queue) {
        return this.queues.add(requireNonNull(queue));
    }

    public boolean removeBlockingQueue(@Nonnull final BlockingQueue<E> queue) {
        return this.queues.remove(requireNonNull(queue));
    }

    @Override
    public boolean add(@Nonnull final E e) {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.add(e);
        }
        return true;
    }

    @Override
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

    @Override
    public E remove() {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public E poll() {
        E polled = null;
        for (final BlockingQueue<E> queue : this.queues) {
            polled = queue.poll();
        }
        return polled;
    }

    @Override
    @Nonnull
    public E element() {
        if (this.queues.isEmpty()) {
            throw new NoSuchElementException("No queues registered, hence no elements exist anywhere.");
        }
        E element = null;
        for (final BlockingQueue<E> queue : this.queues) {
            element = queue.element();
        }
        return element;
    }

    @Override
    public E peek() {
        E peek = null;
        for (final BlockingQueue<E> queue : this.queues) {
            peek = queue.peek();
        }
        return peek;
    }

    @Override
    public void put(@Nonnull final E e) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
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

    @Override
    @Nonnull
    public E take() {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public E poll(final long timeout, @Nonnull final TimeUnit unit) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public int remainingCapacity() {
        if (this.queues.isEmpty()) {
            return 0;
        }
        int minCapacity = Integer.MAX_VALUE;
        for (final BlockingQueue<E> queue : this.queues) {
            minCapacity = min(minCapacity, queue.remainingCapacity());
        }
        return minCapacity;
    }

    @Override
    public boolean remove(final Object o) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public boolean containsAll(@Nonnull final Collection<?> c) {
        for (final BlockingQueue<E> queue : this.queues) {
            if (queue.containsAll(c)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean addAll(@Nonnull final Collection<? extends E> c) {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.addAll(c);
        }
        return true;
    }

    @Override
    public boolean removeAll(@Nonnull final Collection<?> c) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public boolean retainAll(@Nonnull final Collection<?> c) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public void clear() {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.clear();
        }
    }

    @Override
    public int size() {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public boolean isEmpty() {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public boolean contains(final Object o) {
        for (final BlockingQueue<E> queue : this.queues) {
            if (queue.contains(o)) {
                return true;
            }
        }
        return false;
    }

    @Nonnull
    @Override
    public Iterator<E> iterator() {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Nonnull
    @Override
    public Object[] toArray() {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Nonnull
    @Override
    public <T> T[] toArray(@Nonnull final T[] a) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public int drainTo(@Nonnull final Collection<? super E> c) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }

    @Override
    public int drainTo(@Nonnull final Collection<? super E> c, final int maxElements) {
        throw new UnsupportedOperationException("Only submitting new elements is supported.");
    }
}
