package com.ikea.crypto.server.codec.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.AesCipherPayload;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.core.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.rsa.RsaCipherPayload;
import com.ikea.crypto.common.rsa.SessionKeyTransport;
import com.ikea.crypto.server.codec.AbstractCryptoCodec;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.service.RsaCryptoServer;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

@Slf4j
public class RsaCryptoCodec extends AbstractCryptoCodec {
    private final RsaCryptoServer rsaCryptoServer;

    public RsaCryptoCodec(RsaCryptoServer rsaCryptoServer, ObjectMapper objectMapper) {
        super(objectMapper);
        this.rsaCryptoServer = rsaCryptoServer;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.RSA;
    }

    @Override
    protected String doDecrypt(CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        log.debug("Decrypting request body in session context with RSA algorithm");
        if (sessionContext.requestKeyMaterial() instanceof RsaCipherPayload payload) {
            return rsaCryptoServer.decrypt(payload);
        }
        throw new InvalidCryptoPayloadException("Unsupported RSA session key material: " + sessionContext.requestKeyMaterial());
    }

    @Override
    protected Object doEncrypt(String responseBodyString, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        log.debug("Encrypting response body in session context with RSA algorithm");
        if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport sessionKeyTransport) {
            SecretKey sessionKey = new SecretKeySpec(
                    rsaCryptoServer.decryptSessionKey(sessionKeyTransport.encryptedSessionKeyBase64()),
                    CryptoConstants.ALGORITHM_AES
            );

            byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());

            String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(responseBodyString, sessionKey, iv);

            return new AesCipherPayload(
                    EncodingUtils.toBase64(iv),
                    encryptedDataBase64
            );

        }
        if (sessionContext.requestKeyMaterial() instanceof RsaCipherPayload requestPayload) {
            rsaCryptoServer.validatePayload(requestPayload);

            SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();

            if (sessionKey == null) {
                sessionKey = rsaCryptoServer.decryptSessionKeyToSecretKey(requestPayload.encryptedSessionKeyBase64());
            }

            byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());

            String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(responseBodyString, sessionKey, iv);

            return new AesCipherPayload(
                    EncodingUtils.toBase64(iv),
                    encryptedDataBase64
            );

        }
        throw new InvalidCryptoPayloadException("Unsupported RSA session key material: " + sessionContext.requestKeyMaterial());
    }
}
