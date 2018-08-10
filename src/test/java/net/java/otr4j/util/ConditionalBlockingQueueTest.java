package net.java.otr4j.util;

import org.junit.Test;

import javax.annotation.Nonnull;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.singletonList;

@SuppressWarnings("ConstantConditions")
public class ConditionalBlockingQueueTest {

    @Test(expected = NullPointerException.class)
    public void testConstructionNullQueue() {
        new ConditionalBlockingQueue<>(null, new AlwaysFalse<String>());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullCondition() {
        new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), null);
    }

    @Test
    public void testConstruction() {
        new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), new AlwaysFalse<String>());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAdd() {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), new AlwaysFalse<String>());
        queue.add("test");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddAll() {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), new AlwaysFalse<String>());
        queue.addAll(singletonList("test"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testOffer() {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), new AlwaysFalse<String>());
        queue.offer("test");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testOffer2() throws InterruptedException {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), new AlwaysFalse<String>());
        queue.offer("test", 100, TimeUnit.SECONDS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPut() throws InterruptedException {
        final ConditionalBlockingQueue<String> queue = new ConditionalBlockingQueue<>(new LinkedBlockingQueue<String>(), new AlwaysFalse<String>());
        queue.put("test");
    }

    private static final class AlwaysFalse<T> implements ConditionalBlockingQueue.Predicate<T> {

        @Override
        public boolean test(@Nonnull final Object o) {
            return false;
        }
    }
}