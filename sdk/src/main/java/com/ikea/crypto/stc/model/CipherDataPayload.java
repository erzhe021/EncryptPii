package com.ikea.crypto.stc.model;

/**
 * Default AES cipher payload containing the initialization vector and encrypted data.
 */
public record CipherDataPayload(

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64

) {
}
