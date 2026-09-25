package com.ikea.crypto.common;

/**
 * Default AES cipher payload containing the initialization vector and encrypted data.
 */
public record DefaultAesCipherPayload(

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64

) implements AesCipherPayload {
}
