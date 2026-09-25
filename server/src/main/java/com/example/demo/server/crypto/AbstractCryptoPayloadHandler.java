package com.example.demo.server.crypto;

import lombok.extern.slf4j.Slf4j;

import java.security.GeneralSecurityException;

@Slf4j
public abstract class AbstractCryptoPayloadHandler implements CryptoPayloadHandler {
    private final CryptoEnvelopeParser envelopeParser;
    private final CryptoCodec codec;

    protected AbstractCryptoPayloadHandler(CryptoEnvelopeParser envelopeParser, CryptoCodec codec) {
        this.envelopeParser = envelopeParser;
        this.codec = codec;
    }

    @Override
    public final String decrypt(String encryptedRequestBody) throws GeneralSecurityException {
        log.info("decrypt encryptedRequestBody={}", encryptedRequestBody);
        CryptoSessionContext<?> sessionContext = envelopeParser.parse(encryptedRequestBody);
        return codec.decrypt(encryptedRequestBody, sessionContext);
    }

    @Override
    public final CryptoSessionContext<?> createSessionContext(String encryptedRequestBody) {
        log.info("createSessionContext encryptedRequestBody={}", encryptedRequestBody);
        return envelopeParser.parse(encryptedRequestBody);
    }

    @Override
    public final Object encrypt(Object responseBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        log.info("encrypt responseBody={} with sessionContext={}", responseBody, sessionContext);
        return codec.encrypt(responseBody, sessionContext);
    }
}
