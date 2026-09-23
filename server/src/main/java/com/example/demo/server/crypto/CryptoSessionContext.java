package com.example.demo.server.crypto;

public class CryptoSessionContext {
    public static final String REQUEST_CONTEXT_KEY = "crypto.session.context";

    private final CryptoAlgorithm algorithm;
    private final String encryptedRequestBody;
    private final Object requestKeyMaterial;

    public CryptoSessionContext(CryptoAlgorithm algorithm, String encryptedRequestBody, Object requestKeyMaterial) {
        this.algorithm = algorithm;
        this.encryptedRequestBody = encryptedRequestBody;
        this.requestKeyMaterial = requestKeyMaterial;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public String getEncryptedRequestBody() {
        return encryptedRequestBody;
    }

    public Object getRequestKeyMaterial() {
        return requestKeyMaterial;
    }
}
