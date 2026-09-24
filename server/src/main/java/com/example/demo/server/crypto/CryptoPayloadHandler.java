package com.example.demo.server.crypto;

import java.security.GeneralSecurityException;

/**
 * CryptoPayloadHandler is an interface that defines methods for handling cryptographic operations on payloads.
 * Implementations of this interface are responsible for decrypting incoming requests and encrypting outgoing responses
 * using specific cryptographic algorithms.
 */
public interface CryptoPayloadHandler {
    /**
     * Returns the cryptographic algorithm used by this handler.
     *
     * @return the CryptoAlgorithm used for encryption and decryption
     */
    CryptoAlgorithm algorithm();

    /**
     * Decrypts the given request body and returns the decrypted data as a string.
     *
     * @param encryptedRequestBody the encrypted request body
     * @return the decrypted data as a string
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    String decrypt(String encryptedRequestBody) throws GeneralSecurityException;

    /**
     * Creates a CryptoSessionContext based on the given request body.
     *
     * @param encryptedRequestBody the encrypted request body
     * @return a CryptoSessionContext containing information about the cryptographic session
     * @throws GeneralSecurityException if a security exception occurs during session context creation
     */
    CryptoSessionContext createSessionContext(String encryptedRequestBody) throws GeneralSecurityException;

    /**
     * Encrypts the given response body and returns the encrypted data as an object.
     *
     * @param responseBody   the response body to be encrypted
     * @param sessionContext the cryptographic session context
     * @return the encrypted response body as an object
     * @throws GeneralSecurityException if a security exception occurs during encryption
     */
    Object encrypt(Object responseBody, CryptoSessionContext sessionContext) throws GeneralSecurityException;
}
