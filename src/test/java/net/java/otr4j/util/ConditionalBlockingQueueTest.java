/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.util;

import org.junit.Test;

import javax.annotation.Nonnull;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.singletonList;

@SuppressWarnings({"ConstantConditions", "ModifiedButNotUsed"})
public class ConditionalBlockingQueueTest {

    @Test(expected = NullPointerException.class)
    public void testConstructionNullQueue() {
        new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullCondition() {
        new ConditionalBlockingQueue<>(null, new LinkedBlockingQueue<String>());
    }

    @Test
    public void testConstruction() {
        new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), new LinkedBlockingQueue<String>());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAdd() {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), new LinkedBlockingQueue<String>());
        queue.add("test");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddAll() {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), new LinkedBlockingQueue<String>());
        queue.addAll(singletonList("test"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testOffer() {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), new LinkedBlockingQueue<String>());
        queue.offer("test");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testOffer2() throws InterruptedException {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), new LinkedBlockingQueue<String>());
        queue.offer("test", 100, TimeUnit.SECONDS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPut() throws InterruptedException {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new AlwaysFalse<String>(), new LinkedBlockingQueue<String>());
        queue.put("test");
    }

    private static final class AlwaysFalse<T> implements ConditionalBlockingQueue.Predicate<T> {

        @Override
        public boolean test(@Nonnull final Object o) {
            return false;
        }
    }
}
