package com.example.demo.crypto;

import java.security.GeneralSecurityException;

/**
 * PublicKeyProvider is an interface that defines a method for fetching the server's public key.
 * Implementations of this interface should provide the logic to retrieve the public key,
 * which can be used for cryptographic operations.
 */
public interface PublicKeyProvider {
    Object fetchServerPublicKey() throws GeneralSecurityException;
}
