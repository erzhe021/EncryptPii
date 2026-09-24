package com.example.demo.crypto.rsa;

import com.example.demo.crypto.AesCipherPayload;

/**
 * RSA cipher payload containing the encrypted session key, initialization vector, and encrypted data.
 */
public record RsaCipherPayload(
        //session key encrypted with rsa
        String encryptedSessionKeyBase64,

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64
) implements AesCipherPayload {
}
