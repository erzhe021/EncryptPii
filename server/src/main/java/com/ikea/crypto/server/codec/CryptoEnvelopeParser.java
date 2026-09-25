package com.ikea.crypto.server.codec;

import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.context.CryptoSessionContext;

public interface CryptoEnvelopeParser {
    CryptoAlgorithm algorithm();

    CryptoSessionContext<?> parse(String encryptedRequestBody);
}
