package com.example.demo.server.crypto;

import org.springframework.http.MediaType;

import java.lang.reflect.Type;
import java.security.GeneralSecurityException;

public interface CryptoPayloadHandler {
    CryptoAlgorithm algorithm();

    String decrypt(String requestBody, Type targetType) throws GeneralSecurityException;

    CryptoSessionContext createSessionContext(String requestBody) throws GeneralSecurityException;

    Object encrypt(Object responseBody, MediaType mediaType, CryptoSessionContext sessionContext) throws GeneralSecurityException;
}
