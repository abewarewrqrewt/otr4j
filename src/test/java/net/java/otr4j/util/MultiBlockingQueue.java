package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

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
public final class MultiBlockingQueue<E> implements BlockingQueue<E> {

    private final ArrayList<BlockingQueue<E>> queues;

    public MultiBlockingQueue(@Nonnull final Collection<BlockingQueue<E>> queues) {
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
        E removed = null;
        for (final BlockingQueue<E> queue : this.queues) {
            removed = queue.remove();
        }
        return removed;
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
    public void put(@Nonnull final E e) throws InterruptedException {
        for (final BlockingQueue<E> queue : this.queues) {
            queue.put(e);
        }
        // TODO currently, we cannot trust state after an InterruptedException has occurred for 'put' call that was performed on any other than the first queue.
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
    public E take() throws InterruptedException {
        if (this.queues.isEmpty()) {
            throw new IllegalStateException("No queues are added, hence we can wait infinitely. Not gonna try to do that.");
        }
        E taken = null;
        for (final BlockingQueue<E> queue : this.queues) {
            taken = queue.take();
        }
        return taken;
        // TODO currently, we cannot trust state after an InterruptedException has occurred for 'take' call that was performed on any other than the first queue.
    }

    @Override
    public E poll(final long timeout, final TimeUnit unit) throws InterruptedException {
    }

    @Override
    public int remainingCapacity() {

        return 0;
    }

    @Override
    public boolean remove(final Object o) {
    }

    @Override
    public boolean containsAll(final Collection<?> c) {
    }

    @Override
    public boolean addAll(final Collection<? extends E> c) {
    }

    @Override
    public boolean removeAll(final Collection<?> c) {
    }

    @Override
    public boolean retainAll(final Collection<?> c) {
    }

    @Override
    public void clear() {
    }

    @Override
    public int size() {
    }

    @Override
    public boolean isEmpty() {
    }

    @Override
    public boolean contains(final Object o) {
    }

    @Override
    public Iterator<E> iterator() {
    }

    @Override
    public Object[] toArray() {
    }

    @Override
    public <T> T[] toArray(final T[] a) {
    }

    @Override
    public int drainTo(final Collection<? super E> c) {
    }

    @Override
    public int drainTo(final Collection<? super E> c, final int maxElements) {
    }
}
