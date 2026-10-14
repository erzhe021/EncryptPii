package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.model.KeyMetadata;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class KeyRingExceptionHandlingTest {

    private final KeyRing keyRing = new KeyRing("test", 1000, 100, false, 200);

    @Test
    void versionScansSkipMalformedAndOutOfRangeVersions() {
        register("test:3");
        register("test:invalid");
        register("test:9223372036854775808");
        assertThrows(IllegalArgumentException.class, () -> register("other:10"));

        assertEquals(3, keyRing.getCurrentVersion("test"));
        assertEquals(4, keyRing.getNextVersion("test"));
        assertEquals(4, keyRing.getNextVersion(null));
    }

    @Test
    void nextVersionRejectsOverflow() {
        register("test:" + Long.MAX_VALUE);

        assertEquals(Long.MAX_VALUE, keyRing.getCurrentVersion("test"));
        IllegalStateException exception = assertThrows(
                IllegalStateException.class, () -> keyRing.getNextVersion("test"));
        assertInstanceOf(ArithmeticException.class, exception.getCause());
    }

    @Test
    void gracePeriodDeadlineSaturatesOnOverflow() {
        KeyMetadata metadata = new KeyMetadata("test:1", 0, Long.MAX_VALUE - 50);

        assertFalse(keyRing.isExpiredBeyondGrace(metadata, Long.MAX_VALUE - 1));
        assertTrue(keyRing.isExpiredBeyondGrace(metadata, Long.MAX_VALUE));
    }

    @Test
    void malformedMetadataVersionRemainsAbsent() {
        assertNull(new KeyMetadata("test:invalid", 0, 1000).version());
        assertNull(new KeyMetadata("test:9223372036854775808", 0, 1000).version());
        assertEquals(3L, new KeyMetadata("test:3", 0, 1000).version());
    }

    @Test
    void inactiveRegistrationDoesNotSelectAnActiveKey() {
        KeyRing.KeyEntry historical = entry("test:1", System.currentTimeMillis() + 60_000);

        keyRing.registerKeyEntry(historical, false);

        assertNull(keyRing.getActiveKeyEntry());
        assertSame(historical, keyRing.findKeyEntry("test:1").orElseThrow());
    }

    @Test
    void keyRingRejectsEntriesForAliasesOtherThanItsConfiguredAlias() {
        long now = System.currentTimeMillis();
        KeyRing.KeyEntry active = entry("test:2", now + 60_000);
        KeyRing.KeyEntry historical = entry("test:1", now + 120_000);
        KeyRing.KeyEntry other = entry("other:9", now + 180_000);
        keyRing.registerKeyEntry(active, true);

        keyRing.registerKeyEntry(historical, false);

        assertSame(active, keyRing.getActiveKeyEntry());
        assertTrue(keyRing.findActiveKeyEntry("other").isEmpty());
        assertThrows(IllegalArgumentException.class, () -> keyRing.registerKeyEntry(other, false));
        assertThrows(IllegalArgumentException.class, () -> keyRing.rotateKey("other"));
        assertSame(active, keyRing.getActiveKeyEntry());
    }

    @Test
    void retiredKeyGraceStartsAtSuccessorCreationInsteadOfOriginalExpiry() {
        KeyRing.KeyEntry old = entry("test:1", 1_000);
        KeyRing.KeyEntry successor = new KeyRing.KeyEntry(
                new KeyMetadata("test:2", 500, 1_500), new KeyPair(null, null));
        keyRing.registerKeyEntry(old, true);
        keyRing.registerKeyEntry(successor, true);

        assertFalse(keyRing.isExpiredBeyondGrace(old.metadata(), 599));
        assertTrue(keyRing.isExpiredBeyondGrace(old.metadata(), 600));
    }

    @Test
    void reRegisteringWithoutRetirementTimeClearsPreviousOverride() {
        KeyRing.KeyEntry old = entry("test:1", 1_000);
        KeyRing.KeyEntry successor = new KeyRing.KeyEntry(
                new KeyMetadata("test:2", 500, 1_500), new KeyPair(null, null));
        keyRing.registerKeyEntry(old, true);
        keyRing.registerKeyEntry(successor, true);

        keyRing.registerKeyEntry(old, false);

        assertTrue(keyRing.isExpiredBeyondGrace(old.metadata(), 1_200));
    }

    @Test
    void activeLookupReturnsActiveEntryForExplicitAndDefaultAliases() {
        KeyRing.KeyEntry active = entry("test:1", 0);
        keyRing.registerKeyEntry(active, true);

        assertSame(active, keyRing.findActiveKeyEntry("test").orElseThrow());
        assertSame(active, keyRing.findActiveKeyEntry(" test ").orElseThrow());
        assertSame(active, keyRing.findActiveKeyEntry(null).orElseThrow());
        assertSame(active, keyRing.findActiveKeyEntry(" ").orElseThrow());
    }

    @Test
    void activeLookupFallsBackToLatestValidHistoricalEntry() {
        KeyRing.KeyEntry historical = entry("test:2", Long.MAX_VALUE - 100);
        keyRing.registerKeyEntry(entry("test:1", Long.MAX_VALUE - 100), false);
        keyRing.registerKeyEntry(historical, false);

        assertSame(historical, keyRing.findActiveKeyEntry("test").orElseThrow());
        assertTrue(keyRing.findActiveKeyEntry(null).isEmpty());
    }

    @Test
    void currentVersionRetainsActiveFallbackWhenNoPositiveVersionIsPresent() {
        assertEquals(0, keyRing.getCurrentVersion("test"));
        keyRing.registerKeyEntry(entry("test:-1", 0), true);

        assertEquals(-1, keyRing.getCurrentVersion("test"));
        assertEquals(-1, keyRing.getCurrentVersion(null));
    }

    private KeyRing.KeyEntry entry(String keyId, long expiresAt) {
        return new KeyRing.KeyEntry(new KeyMetadata(keyId, 0, expiresAt), new KeyPair(null, null));
    }

    private void register(String keyId) {
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(
                new KeyMetadata(keyId, 0, System.currentTimeMillis() + 60_000),
                new KeyPair(null, null)), true);
    }
}
