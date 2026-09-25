package com.ikea.crypto.server.codec;

import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.context.CryptoSessionContext;

import java.security.GeneralSecurityException;

public interface CryptoCodec {
    CryptoAlgorithm algorithm();

    String decrypt(String encryptedRequestBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException;

    Object encrypt(Object responseBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException;
}
