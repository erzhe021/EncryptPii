package com.example.demo.server.crypto.ecdh;

import com.example.demo.server.crypto.AbstractCryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EcdhCryptoPayloadHandler extends AbstractCryptoPayloadHandler {
    public EcdhCryptoPayloadHandler(EcdhCryptoServer ecdhCryptoServer, ObjectMapper objectMapper) {
        super(new EcdhCryptoEnvelopeParser(objectMapper), new EcdhCryptoCodec(ecdhCryptoServer, objectMapper));
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }
}
