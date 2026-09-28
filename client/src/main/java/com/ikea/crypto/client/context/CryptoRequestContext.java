package com.ikea.crypto.client.context;

import javax.crypto.SecretKey;

/**
 * CryptoRequestContext is a record that holds the context for a cryptographic request.
 *
 * @param requestId  The unique identifier for the request.
 * @param sessionKey The session key used for encryption/decryption.
 * @param iv         The initialization vector used for encryption/decryption.
 */
public record CryptoRequestContext(
            String requestId,
            SecretKey sessionKey,
            byte[] iv
) {
}
