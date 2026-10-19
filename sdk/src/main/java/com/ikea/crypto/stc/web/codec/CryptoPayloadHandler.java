package com.ikea.crypto.stc.web.codec;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.GcmIvGenerator;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.exception.CryptoServerSideException;
import com.ikea.crypto.stc.exception.ResponseEncryptionException;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.SessionKeyHeaders;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.util.EncodingUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Handles the processing of encrypted payloads for both requests and responses.
 * This class is responsible for creating session contexts, decrypting request bodies,
 * and encrypting response bodies using the provided CryptoServer and ObjectMapper.
 */
public class CryptoPayloadHandler {

    private final CryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    private static final String IV_FIELD = "ivBase64";
    private static final String ENCRYPTED_DATA_FIELD = "encryptedDataBase64";

    public CryptoPayloadHandler(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = Objects.requireNonNull(cryptoServer, "cryptoServer is required");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper is required");
    }

    public CryptoSessionContext createSessionContext(String encryptedRequestBody, SessionKeyHeaders sessionKeyHeaders) {
        if (sessionKeyHeaders == null) {
            throw new InvalidCryptoRequestException("Session key headers are required.");
        }
        if (encryptedRequestBody == null || encryptedRequestBody.isBlank()) {
            throw new InvalidCryptoRequestException("Encrypted request body is required.");
        }
        try (JsonParser parser = objectMapper.getFactory().createParser(encryptedRequestBody)) {
            parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
            JsonNode body = objectMapper.readTree(parser);
            if (body == null || !body.isObject()
                    || body.size() != 2
                    || !body.has(IV_FIELD)
                    || !body.has(ENCRYPTED_DATA_FIELD)
                    || !body.get(IV_FIELD).isTextual()
                    || !body.get(ENCRYPTED_DATA_FIELD).isTextual()) {
                throw new InvalidCryptoRequestException(
                        "Request body may contain only ivBase64 and encryptedDataBase64");
            }
            if (parser.nextToken() != null) {
                throw new InvalidCryptoRequestException("Request body must contain exactly one JSON object.");
            }
            CipherRequestPayload payload = new CipherRequestPayload(
                    body.get(IV_FIELD).asText(null),
                    body.get(ENCRYPTED_DATA_FIELD).asText(null));
            cryptoServer.validatePayload(payload);
            return CryptoSessionContext.request(payload, sessionKeyHeaders);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoRequestException("Invalid encrypted request payload", e);
        } catch (IOException e) {
            throw new CryptoServerSideException("Failed to read encrypted request payload", e);
        }
    }

    public CryptoSessionContext createFormSessionContext(String encryptedRequestBody,
                                                         SessionKeyHeaders sessionKeyHeaders) {
        if (encryptedRequestBody == null || encryptedRequestBody.isBlank()) {
            throw new InvalidCryptoRequestException("Encrypted request body is required.");
        }
        Map<String, String> fields = new HashMap<>();
        for (String pair : encryptedRequestBody.split("&", -1)) {
            int separator = pair.indexOf('=');
            if (separator < 0) {
                throw new InvalidCryptoRequestException("Invalid URL-encoded encrypted request payload.");
            }
            try {
                String name = URLDecoder.decode(pair.substring(0, separator), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(separator + 1), StandardCharsets.UTF_8);
                if (fields.putIfAbsent(name, value) != null) {
                    throw new InvalidCryptoRequestException("Duplicate field in encrypted request payload.");
                }
            } catch (IllegalArgumentException e) {
                throw new InvalidCryptoRequestException("Invalid URL-encoded encrypted request payload.", e);
            }
        }
        if (fields.size() != 2 || !fields.containsKey(IV_FIELD) || !fields.containsKey(ENCRYPTED_DATA_FIELD)) {
            throw new InvalidCryptoRequestException(
                    "Request body may contain only ivBase64 and encryptedDataBase64");
        }
        try {
            return createSessionContext(objectMapper.writeValueAsString(fields), sessionKeyHeaders);
        } catch (JsonProcessingException e) {
            throw new CryptoServerSideException("Failed to serialize URL-encoded encrypted request payload", e);
        }
    }

    public String decrypt(CryptoSessionContext sessionContext) throws GeneralSecurityException {
        if (sessionContext == null) {
            throw new CryptoServerSideException("Crypto session context is required for request decryption");
        }
        CipherRequestPayload payload = sessionContext.requireRequestPayload();
        SessionKeyHeaders headers = sessionContext.sessionKeyHeaders();
        SecretKey sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                headers.keyId(), headers.encryptedSessionKeyBase64());
        String decryptedBody = cryptoServer.decrypt(payload, sessionKey);
        CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
        return decryptedBody;
    }

    public CryptoSessionContext createResponseSessionContext(SessionKeyHeaders headers) {
        if (headers == null) {
            throw new InvalidCryptoRequestException("Session key headers are required.");
        }
        CryptoSessionContext context = CryptoSessionContext.responseOnly(headers);
        try {
            SecretKey sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                    headers.keyId(), headers.encryptedSessionKeyBase64());
            CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
            return context;
        } catch (GeneralSecurityException e) {
            throw new CryptoServerSideException("Failed to initialize session key decryption", e);
        }
    }

    public Object encrypt(Object responseBody, CryptoSessionContext sessionContext) {
        if (sessionContext == null) {
            throw new ResponseEncryptionException("Crypto session context is required for response encryption");
        }
        String responseBodyString;
        try {
            responseBodyString = objectMapper.writeValueAsString(responseBody);
        } catch (JsonProcessingException e) {
            throw new ResponseEncryptionException("Failed to serialize response body before encryption", e);
        }

        try {
            SecretKey sessionKey = CryptoSessionContextAccessor.getCryptoSessionContext() == sessionContext
                    ? CryptoSessionContextAccessor.getResolvedSessionKey()
                    : null;
            if (sessionKey == null) {
                SessionKeyHeaders headers = sessionContext.sessionKeyHeaders();
                sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                        headers.keyId(), headers.encryptedSessionKeyBase64());
            }
            byte[] iv = GcmIvGenerator.generateIv();
            String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(responseBodyString, sessionKey, iv);
            return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }
    }
}
