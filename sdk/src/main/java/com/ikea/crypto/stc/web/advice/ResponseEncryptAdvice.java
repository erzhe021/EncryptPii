package com.ikea.crypto.stc.web.advice;

import com.ikea.crypto.stc.annotation.EncryptResponse;
import com.ikea.crypto.stc.exception.ResponseEncryptionException;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import com.ikea.crypto.stc.constant.CryptoConstants;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

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
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body,
                                  MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        log.debug("【api post-called】start to encrypting response body");
        CryptoSessionContext sessionContext = CryptoSessionContextAccessor.getCryptoSessionContext();
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        // Exception handlers have their own return type; preserve the original route's policy.
        if (encryptResponse == null && sessionContext != null && request instanceof ServletServerHttpRequest servletRequest) {
            Object handler = servletRequest.getServletRequest()
                    .getAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE);
            if (handler instanceof HandlerMethod handlerMethod) {
                encryptResponse = findEncryptResponse(handlerMethod.getReturnType());
            }
        }
        if (encryptResponse == null || "false".equalsIgnoreCase(
                response.getHeaders().getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED))) {
            CryptoSessionContextAccessor.clearCryptoSessionContext();
            return body;
        }
        if (body == null) {
            CryptoSessionContextAccessor.clearCryptoSessionContext();
            return null;
        }
        try {
            // Get the CryptoSessionContext for response encryption
            if (sessionContext == null) {
                throw new ResponseEncryptionException("No request session context available for response encryption");
            }
            // Encrypt the response body using the handler
            Object encryptedBody = payloadHandler.encrypt(body, sessionContext);
            response.getHeaders().set(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED, "true");
            return encryptedBody;
        } finally {
            CryptoSessionContextAccessor.clearCryptoSessionContext();
        }
    }

    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        return CryptoAdviceSupport.findAnnotation(returnType, EncryptResponse.class);
    }
}
