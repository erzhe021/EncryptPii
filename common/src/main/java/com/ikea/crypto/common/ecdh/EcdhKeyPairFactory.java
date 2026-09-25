package com.ikea.crypto.common.ecdh;

import com.ikea.crypto.common.CryptoConstants;
import lombok.extern.slf4j.Slf4j;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

@Slf4j
public final class EcdhKeyPairFactory {

    private EcdhKeyPairFactory() {
    }

    public static KeyPair generateEphemeralKeyPair() throws GeneralSecurityException {
        return generateEphemeralKeyPair(null);
    }

    public static KeyPair generateEphemeralKeyPair(SecureRandom secureRandom) throws GeneralSecurityException {
        log.info("Generating ephemeral ECDH key pair using curve: {}", CryptoConstants.CURVE_ECDH);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        if (secureRandom != null) {
            keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH), secureRandom);
        } else {
            keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        }
        return keyPairGenerator.generateKeyPair();
    }
}
