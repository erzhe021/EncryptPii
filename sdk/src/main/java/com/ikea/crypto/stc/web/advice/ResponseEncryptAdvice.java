package com.ikea.crypto.stc.web.advice;

import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.exception.CryptoException;
import com.ikea.crypto.stc.exception.ResponseEncryptionException;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.security.GeneralSecurityException;

@ControllerAdvice
@Slf4j
public class ResponseEncryptAdvice implements ResponseBodyAdvice<Object> {

    private final CryptoPayloadHandler payloadHandler;

    public ResponseEncryptAdvice(CryptoPayloadHandler payloadHandler) {
        this.payloadHandler = payloadHandler;
    }

    @Override
    public boolean supports(MethodParameter returnType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return findEncryptResponse(returnType) != null;
    }

    @Override
    public Object beforeBodyWrite(Object body,
                                  MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        log.debug("【api post-called】start to encrypting response body");
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        if (encryptResponse == null || body == null) {
            return body;
        }
        try {
            // Get the CryptoSessionContext for response encryption
            CryptoSessionContext sessionContext = CryptoSessionContextAccessor.getCryptoSessionContext();
            if (sessionContext == null) {
                throw new ResponseEncryptionException("No request session context available for response encryption");
            }
            // Encrypt the response body using the handler
            return payloadHandler.encrypt(body, sessionContext);
        } catch (CryptoException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        } finally {
            CryptoSessionContextAccessor.clearCryptoSessionContext();
        }
    }

    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        return CryptoAdviceSupport.findAnnotation(returnType, EncryptResponse.class);
    }
}
