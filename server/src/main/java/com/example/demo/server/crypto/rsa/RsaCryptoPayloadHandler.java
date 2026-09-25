package com.example.demo.server.crypto.rsa;

import com.example.demo.server.crypto.AbstractCryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * RsaCryptoPayloadHandler is responsible for handling RSA encrypted payloads.
 * It provides methods to decrypt incoming requests and encrypt outgoing responses using RSA and AES algorithms.
 */
public class RsaCryptoPayloadHandler extends AbstractCryptoPayloadHandler {
    public RsaCryptoPayloadHandler(RsaCryptoServer rsaCryptoServer, ObjectMapper objectMapper) {
        super(new RsaCryptoEnvelopeParser(objectMapper), new RsaCryptoCodec(rsaCryptoServer, objectMapper));
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.RSA;
    }
}
