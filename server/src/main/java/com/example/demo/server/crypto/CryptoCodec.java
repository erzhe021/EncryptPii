package com.example.demo.server.crypto;

import java.security.GeneralSecurityException;

public interface CryptoCodec {
    CryptoAlgorithm algorithm();

    String decrypt(String encryptedRequestBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException;

    Object encrypt(Object responseBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException;
}
