package com.ikea.crypto.server;

import com.ikea.crypto.stc.config.KeyLifecycleProperties;
import com.ikea.crypto.stc.key.KeyRing;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeyLifecycleDefaultsTest {

    @Test
    void defaultKeyRingUsesKeyLifecyclePropertyDefaults() {
        KeyLifecycleProperties defaults = new KeyLifecycleProperties();
        KeyRing keyRing = new KeyRing("default-key");

        assertEquals(defaults.getValidityMillis(), keyRing.getValidityMillis());
        assertEquals(defaults.getGracePeriodMillis(), keyRing.getGracePeriodMillis());
        assertEquals(defaults.getRotationBeforeExpiryMillis(), keyRing.getRotationBeforeExpiryMillis());
    }
}
