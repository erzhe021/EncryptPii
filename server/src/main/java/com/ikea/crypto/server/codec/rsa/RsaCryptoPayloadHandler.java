package com.ikea.crypto.server.codec.rsa;

import com.ikea.crypto.server.codec.AbstractCryptoPayloadHandler;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.service.RsaCryptoServer;
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
