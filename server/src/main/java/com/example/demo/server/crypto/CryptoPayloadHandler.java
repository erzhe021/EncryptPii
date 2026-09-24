package com.example.demo.server.crypto;

import org.springframework.http.MediaType;

import java.lang.reflect.Type;
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
     * @param requestBody the encrypted request body
     * @param targetType  the target type of the decrypted data
     * @return the decrypted data as a string
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    String decrypt(String requestBody, Type targetType) throws GeneralSecurityException;

    /**
     * Creates a CryptoSessionContext based on the given request body.
     *
     * @param requestBody the encrypted request body
     * @return a CryptoSessionContext containing information about the cryptographic session
     * @throws GeneralSecurityException if a security exception occurs during session context creation
     */
    CryptoSessionContext createSessionContext(String requestBody) throws GeneralSecurityException;

    /**
     * Encrypts the given response body and returns the encrypted data as an object.
     *
     * @param responseBody   the response body to be encrypted
     * @param mediaType      the media type of the response
     * @param sessionContext the cryptographic session context
     * @return the encrypted response body as an object
     * @throws GeneralSecurityException if a security exception occurs during encryption
     */
    Object encrypt(Object responseBody, MediaType mediaType, CryptoSessionContext sessionContext) throws GeneralSecurityException;
}
