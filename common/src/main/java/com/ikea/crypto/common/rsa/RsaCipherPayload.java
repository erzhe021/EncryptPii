package com.ikea.crypto.common.rsa;

import com.ikea.crypto.common.AesCipherPayload;

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
