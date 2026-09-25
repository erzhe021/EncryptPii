package com.example.demo.server.crypto;

public interface CryptoEnvelopeParser {
    CryptoAlgorithm algorithm();

    CryptoSessionContext<?> parse(String encryptedRequestBody);
}
