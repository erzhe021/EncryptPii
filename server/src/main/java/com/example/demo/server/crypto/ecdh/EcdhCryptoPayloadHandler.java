package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhContext;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.InvalidCryptoPayloadException;
import com.example.demo.server.crypto.ResponseEncryptionException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;

@Component
@Slf4j
public class EcdhCryptoPayloadHandler implements CryptoPayloadHandler {
    private final EcdhCryptoServer ecdhCryptoServer;
    private final ObjectMapper objectMapper;

    public EcdhCryptoPayloadHandler(EcdhCryptoServer ecdhCryptoServer, ObjectMapper objectMapper) {
        this.ecdhCryptoServer = ecdhCryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }

    /**
     * Decrypts the given encrypted request body using ECDH.
     *
     * @param encryptedRequestBody The encrypted request body as a JSON string.
     * @return The decrypted request body as a string.
     * @throws GeneralSecurityException If there is an error during decryption.
     */
    @Override
    public String decrypt(String encryptedRequestBody) throws GeneralSecurityException {
        log.info("decrypt encryptedRequestBody={}", encryptedRequestBody);
        try {
            EcdhCipherPayload payload = objectMapper.readValue(encryptedRequestBody, EcdhCipherPayload.class);
            return ecdhCryptoServer.decrypt(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Invalid ECDH encrypted request payload", e);
        }
    }

    /**
     * Creates a CryptoSessionContext based on the given encrypted request body.
     *
     * @param encryptedRequestBody The encrypted request body as a JSON string.
     * @return A CryptoSessionContext containing information about the cryptographic session.
     */
    @Override
    public CryptoSessionContext<?> createSessionContext(String encryptedRequestBody) {
        log.info("createSessionContext encryptedRequestBody={}", encryptedRequestBody);
        try {
            EcdhCipherPayload payload = objectMapper.readValue(encryptedRequestBody, EcdhCipherPayload.class);
            return CryptoSessionContext.ecdh(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Invalid ECDH encrypted request payload", e);
        }
    }

    /**
     * Encrypts the response body using the session context.
     *
     * @param responseBody   The response body to encrypt.
     * @param sessionContext The session context containing the encryption parameters.
     * @return The encrypted response body.
     * @throws GeneralSecurityException If there is an error during encryption.
     */
    @Override
    public Object encrypt(Object responseBody, CryptoSessionContext<?> sessionContext)
            throws GeneralSecurityException {

        log.info("encrypt responseBody={} with sessionContext={}", responseBody, sessionContext);

        try {
            String responseBodyString = objectMapper.writeValueAsString(responseBody);
            if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport) {
                throw new InvalidCryptoPayloadException(
                        "SessionKeyTransport is not supported for ECDH response encryption; use EcdhContext or EcdhCipherPayload instead."
                );
            }
            if (sessionContext.requestKeyMaterial() instanceof EcdhContext ecdhContext) {
                return ecdhCryptoServer.encryptWithEcdhContext(responseBodyString, ecdhContext);
            }
            if (sessionContext.requestKeyMaterial() instanceof EcdhCipherPayload requestPayload) {
                EcdhContext ecdhContext = new EcdhContext(
                        requestPayload.clientEphemeralPublicKeyBase64(),
                        requestPayload.serverEphemeralPublicKeyBase64()
                );
                return ecdhCryptoServer.encryptWithEcdhContext(responseBodyString, ecdhContext);
            }
            throw new InvalidCryptoPayloadException("Unsupported ECDH session key material: " + sessionContext.requestKeyMaterial());
        } catch (JsonProcessingException e) {
            throw new ResponseEncryptionException("Failed to serialize response body before ECDH encryption", e);
        }
    }
}
