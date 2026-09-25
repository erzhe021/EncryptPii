package com.ikea.crypto.server.codec.ecdh;

import com.ikea.crypto.server.codec.AbstractCryptoPayloadHandler;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.service.EcdhCryptoServer;
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
