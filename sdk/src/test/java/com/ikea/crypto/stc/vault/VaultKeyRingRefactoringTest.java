package com.ikea.crypto.stc.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.config.KeyLifecycleProperties;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.key.KeyRing.KeyEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VaultKeyRingRefactoringTest {

    private final VaultClient client = mock(VaultClient.class);
    private final VaultProperties properties = new VaultProperties();
    private final KeyLifecycleProperties lifecycle = new KeyLifecycleProperties();
    private VaultKeyRing keyRing;
    private JsonNode keyData;
    private long now;

    @BeforeEach
    void setUp() throws Exception {
        properties.setKeyAlias("test");
        properties.setSecretPath("keys/test");
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("test-token");
        properties.setAutoBootstrap(false);
        lifecycle.setValidityMillis(3_600_000);
        lifecycle.setRotationBeforeExpiryMillis(600_000);
        lifecycle.setGracePeriodMillis(60_000);
        keyRing = new VaultKeyRing(properties, lifecycle, client, false);
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        keyData = new ObjectMapper().valueToTree(keyRing.getCodec().serializeKeyPair(pair));
        now = System.currentTimeMillis();
    }

    @Test
    void initializationSkipsMissingHistoricalVersion() throws Exception {
        stubVersion(null, 3, now);
        stubVersion(1, 1, now - 10_000);

        keyRing.initialize();

        assertEquals("test:3", keyRing.getActiveKeyEntry().metadata().keyId());
        assertEquals(2, keyRing.getAllKeyEntries().size());
        verify(client).readSecretVersion("test-token", "keys/test", 1);
    }

    @Test
    void initializationStopsWhenHistoricalGracePeriodExpires() throws Exception {
        stubVersion(null, 3, now - 120_000);
        stubVersion(2, 2, now - 180_000);

        keyRing.initialize();

        assertEquals(1, keyRing.getAllKeyEntries().size());
        verify(client, never()).readSecretVersion("test-token", "keys/test", 1);
    }

    @Test
    void initializationSkipsMalformedHistoricalKey() throws Exception {
        stubVersion(null, 3, now);
        when(client.readSecretVersion("test-token", "keys/test", 2)).thenReturn(Optional.of(
                new VaultClient.VaultSecretEntry(new ObjectMapper().createObjectNode(), 2,
                        Instant.ofEpochMilli(now - 5_000).toString())));
        stubVersion(1, 1, now - 10_000);

        keyRing.initialize();

        assertEquals(2, keyRing.getAllKeyEntries().size());
    }

    @Test
    void fetchingRetiredKeyDoesNotReplaceNewerActiveKey() throws Exception {
        stubVersion(2, 2, now);
        stubVersion(1, 1, now - 10_000);
        KeyEntry active = keyRing.findKeyEntry("test:2").orElseThrow();

        assertTrue(keyRing.findKeyEntry("test:1").isPresent());
        assertSame(active, keyRing.getActiveKeyEntry());
    }

    @Test
    void fetchingRejectsKeyOutsideGracePeriod() throws Exception {
        stubVersion(1, 1, now - 180_000);
        stubVersion(2, 2, now - 120_000);

        assertTrue(keyRing.findKeyEntry("test:1").isEmpty());
        assertTrue(keyRing.getAllKeyEntries().isEmpty());
    }

    @Test
    void fetchingMaximumVersionDoesNotOverflowNextVersion() {
        stubVersion(Integer.MAX_VALUE, Integer.MAX_VALUE, now);

        assertTrue(keyRing.findKeyEntry("test:" + Integer.MAX_VALUE).isPresent());
        verify(client, never()).readSecretVersion("test-token", "keys/test", Integer.MIN_VALUE);
    }

    @Test
    void fetchingOtherAliasDoesNotReplaceDefaultActiveKey() throws Exception {
        stubVersion(2, 2, now - 10_000);
        KeyEntry active = keyRing.findKeyEntry("test:2").orElseThrow();
        stubAliasVersion("other", 9, 9, now);

        KeyEntry other = keyRing.findKeyEntry("other:9").orElseThrow();

        assertSame(active, keyRing.getActiveKeyEntry());
        assertSame(other, keyRing.findActiveKeyEntry("other").orElseThrow());
    }

    @Test
    void fetchingNewerVersionPromotesOnlyWithinTheActiveAlias() throws Exception {
        stubVersion(1, 1, now - 10_000);
        KeyEntry old = keyRing.findKeyEntry("test:1").orElseThrow();
        stubVersion(2, 2, now);

        KeyEntry latest = keyRing.findKeyEntry("test:2").orElseThrow();

        assertSame(latest, keyRing.getActiveKeyEntry());
        assertFalse(keyRing.isExpiredBeyondGrace(old.metadata(), now + 59_999));
        assertTrue(keyRing.isExpiredBeyondGrace(old.metadata(), now + 60_000));
    }

    @Test
    void fetchingRetiredVersionIntoEmptyRingDoesNotPromoteIt() {
        stubVersion(1, 1, now - 10_000);
        stubVersion(2, 2, now);

        assertTrue(keyRing.findKeyEntry("test:1").isPresent());
        assertNull(keyRing.getActiveKeyEntry());
    }

    @Test
    void fetchingOlderVersionWithLaterExpiryDoesNotPromoteIt() {
        stubVersion(3, 3, now - 10_000);
        KeyEntry active = keyRing.findKeyEntry("test:3").orElseThrow();
        stubVersion(1, 1, now);

        assertTrue(keyRing.findKeyEntry("test:1").isPresent());
        assertSame(active, keyRing.getActiveKeyEntry());
    }

    @Test
    void invalidKeyIdsNeverReachVault() {
        for (String id : new String[]{"test:0", "test:-1", "test:+1", "test:01", ":1", "test:bad"}) {
            assertTrue(keyRing.findKeyEntry(id).isEmpty(), id);
        }

        verifyNoInteractions(client);
    }

    @Test
    void syncingUnchangedAliasReturnsItsEntryRatherThanGlobalActive() throws Exception {
        stubVersion(2, 2, now);
        KeyEntry testEntry = keyRing.findKeyEntry("test:2").orElseThrow();
        stubAliasVersion("other", null, 9, now);
        KeyEntry otherEntry = keyRing.syncLatestKeyFromVault("other");
        stubVersion(null, 2, now);

        assertSame(testEntry, keyRing.syncLatestKeyFromVault(" test "));
        assertSame(otherEntry, keyRing.getActiveKeyEntry());
        assertNull(keyRing.syncLatestKeyFromVault("missing"));
    }

    @Test
    void initializationFailsWhenBootstrapIsDisabledAndVaultIsEmpty() {
        assertThrows(IllegalStateException.class, keyRing::initialize);
    }

    private void stubVersion(Integer requestedVersion, int version, long createdAt) {
        stubAliasVersion("test", requestedVersion, version, createdAt);
    }

    private void stubAliasVersion(String alias, Integer requestedVersion, int version, long createdAt) {
        when(client.readSecretVersion("test-token", "keys/" + alias, requestedVersion))
                .thenReturn(Optional.of(new VaultClient.VaultSecretEntry(
                        keyData, version, Instant.ofEpochMilli(createdAt).toString())));
    }
}
