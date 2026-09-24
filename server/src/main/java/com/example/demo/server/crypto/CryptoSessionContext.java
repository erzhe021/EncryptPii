package com.example.demo.server.crypto;

/**
 * CryptoSessionContext holds the context of a cryptographic session, including the algorithm used,
 * the encrypted request body, and any request-specific key material.
 *
 * @param algorithm            The cryptographic algorithm used for the session.
 * @param encryptedRequestBody  The encrypted request body as a string.
 * @param requestKeyMaterial    The key material associated with the request, which may vary based on the algorithm.
 */
public record CryptoSessionContext(CryptoAlgorithm algorithm,
                                   String encryptedRequestBody,
                                   Object requestKeyMaterial) {
    public static final String REQUEST_CONTEXT_KEY = "crypto.session.context";

}
