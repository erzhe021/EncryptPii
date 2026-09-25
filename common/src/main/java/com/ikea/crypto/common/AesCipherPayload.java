package com.ikea.crypto.common;

/**
 * Represents the payload of an AES cipher, including the initialization vector and the encrypted data.
 */
public interface AesCipherPayload {

    //initialization vector for aes
    String ivBase64();

    //data encrypted with aes
    String encryptedDataBase64();
}
