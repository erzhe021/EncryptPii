package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.model.KeyMetadata;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class KeyRingConcurrencyTest {

    @Test
    void expiredEntryPromotedDuringLookupIsRetained() throws Exception {
        KeyRing.KeyEntry expired = entry(0);

        assertRetainedDuringLookup(expired, expired, ring -> ring.registerKeyEntry(expired, true));
    }

    @Test
    void expiredEntryReplacedWithActiveEntryDuringLookupReturnsReplacement() throws Exception {
        KeyRing.KeyEntry replacement = entry(0);

        assertRetainedDuringLookup(entry(0), replacement, ring -> ring.registerKeyEntry(replacement, true));
    }

    @Test
    void expiredEntryReplacedWithValidHistoricalEntryDuringLookupReturnsReplacement() throws Exception {
        KeyRing.KeyEntry replacement = entry(Long.MAX_VALUE - 100);

        assertRetainedDuringLookup(entry(0), replacement, ring -> ring.registerKeyEntry(replacement, false));
    }

    @Test
    void retirementDeadlineExtendedDuringLookupRetainsEntry() throws Exception {
        KeyRing.KeyEntry expired = entry(0);

        assertRetainedDuringLookup(expired, expired,
                ring -> ring.registerKeyEntry(expired, false, Long.MAX_VALUE - 100));
    }

    @Test
    void expiredHistoricalEntryIsStillPurged() {
        KeyRing ring = new KeyRing("test", 1000, 100, false, 200);
        ring.registerKeyEntry(entry(0), false);

        assertTrue(ring.findKeyEntry("test:1").isEmpty());
        assertTrue(ring.getAllKeyEntries().isEmpty());
    }

    @Test
    void allKeyEntriesSnapshotIsUnmodifiableAndUnaffectedByLaterChanges() {
        KeyRing ring = new KeyRing("test", 1000, 100, false, 200);
        KeyRing.KeyEntry original = entry(Long.MAX_VALUE - 100);
        ring.registerKeyEntry(original, false);
        Collection<KeyRing.KeyEntry> snapshot = ring.getAllKeyEntries();
        var iterator = snapshot.iterator();
        KeyRing.KeyEntry replacement = entry(Long.MAX_VALUE - 200);
        KeyRing.KeyEntry added = new KeyRing.KeyEntry(
                new KeyMetadata("test:2", 0, Long.MAX_VALUE - 100), new KeyPair(null, null));

        ring.registerKeyEntry(replacement, false);
        ring.registerKeyEntry(added, false);

        assertEquals(List.of(original), List.copyOf(snapshot));
        assertSame(original, iterator.next());
        assertFalse(iterator.hasNext());
        assertEquals(2, ring.getAllKeyEntries().size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.add(added));
        assertThrows(UnsupportedOperationException.class, () -> snapshot.remove(original));

        ring.purgeExpiredKeys(Long.MAX_VALUE);

        assertTrue(ring.getAllKeyEntries().isEmpty());
        assertEquals(List.of(original), List.copyOf(snapshot));
    }

    @Test
    void allKeyEntriesSnapshotExcludesExpiredHistoryButRetainsExpiredActiveKey() {
        KeyRing ring = new KeyRing("test", 1000, 100, false, 200);
        KeyRing.KeyEntry active = entry(0);
        KeyRing.KeyEntry expired = new KeyRing.KeyEntry(
                new KeyMetadata("test:2", 0, 0), new KeyPair(null, null));
        ring.registerKeyEntry(active, true);
        ring.registerKeyEntry(expired, false);

        assertEquals(List.of(active), List.copyOf(ring.getAllKeyEntries()));
        assertTrue(ring.findKeyEntry("test:2").isEmpty());
        assertSame(active, ring.getActiveKeyEntry());
    }

    private void assertRetainedDuringLookup(
            KeyRing.KeyEntry original, KeyRing.KeyEntry expected, Consumer<KeyRing> update) throws Exception {
        BlockingExpiryKeyRing ring = new BlockingExpiryKeyRing();
        ring.registerKeyEntry(original, false);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            var lookup = executor.submit(() -> ring.findKeyEntry("test:1"));
            assertTrue(ring.expiryChecked.await(5, TimeUnit.SECONDS), "Lookup did not reach expiry check");
            update.accept(ring);
            ring.continueLookup.countDown();

            Optional<KeyRing.KeyEntry> result = lookup.get(5, TimeUnit.SECONDS);
            assertSame(expected, result.orElseThrow());
            assertSame(expected, ring.findKeyEntry("test:1").orElseThrow());
            assertTrue(ring.getAllKeyEntries().contains(expected));
        } finally {
            ring.continueLookup.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "Lookup executor did not terminate");
        }
    }

    private KeyRing.KeyEntry entry(long expiresAt) {
        return new KeyRing.KeyEntry(
                new KeyMetadata("test:1", 0, expiresAt), new KeyPair(null, null));
    }

    private static class BlockingExpiryKeyRing extends KeyRing {
        private final AtomicBoolean firstCheck = new AtomicBoolean(true);
        private final CountDownLatch expiryChecked = new CountDownLatch(1);
        private final CountDownLatch continueLookup = new CountDownLatch(1);

        private BlockingExpiryKeyRing() {
            super("test", 1000, 100, false, 200);
        }

        @Override
        public boolean isExpiredBeyondGrace(KeyMetadata metadata) {
            boolean expired = super.isExpiredBeyondGrace(metadata);
            if (firstCheck.compareAndSet(true, false)) {
                expiryChecked.countDown();
                try {
                    assertTrue(continueLookup.await(5, TimeUnit.SECONDS), "Lookup was not released");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("Lookup interrupted during expiry check", e);
                }
            }
            return expired;
        }
    }
}
