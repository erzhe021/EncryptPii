package com.ikea.crypto.stc.web;

import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.model.SessionKeyHeaders;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.web.advice.CryptoAdviceSupport;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Collections;

public final class CryptoRequestInterceptor implements HandlerInterceptor {
    private final boolean serverEnabled;
    private final ObjectProvider<CryptoPayloadHandler> payloadHandler;

    public CryptoRequestInterceptor(boolean serverEnabled, ObjectProvider<CryptoPayloadHandler> payloadHandler) {
        this.serverEnabled = serverEnabled;
        this.payloadHandler = payloadHandler;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        HttpHeaders headers = new HttpHeaders();
        for (String name : Collections.list(request.getHeaderNames())) {
            headers.put(name, Collections.list(request.getHeaders(name)));
        }
        boolean enabled = CryptoRequestMode.parse(headers);
        if (!enabled) {
            CryptoRequestMode.setEnabled(request, false);
            return true;
        }
        if (!serverEnabled) {
            throw new InvalidCryptoRequestException("Server transport crypto is disabled.");
        }
        if (!(handler instanceof HandlerMethod method)) {
            throw new InvalidCryptoRequestException("Endpoint does not support transport crypto.");
        }
        boolean decrypt = CryptoAdviceSupport.findAnnotation(method.getReturnType(), DecryptRequest.class) != null;
        boolean encrypt = CryptoAdviceSupport.findAnnotation(method.getReturnType(), EncryptResponse.class) != null;
        if (!decrypt && !encrypt) {
            throw new InvalidCryptoRequestException("Endpoint does not support transport crypto.");
        }
        String keyId = requiredHeader(headers, CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID);
        String sessionKey = requiredHeader(headers, CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY);
        CryptoRequestMode.setEnabled(request, true);
        if (!decrypt) {
            CryptoSessionContextAccessor.setCryptoSessionContext(
                    payloadHandler.getObject().createResponseSessionContext(new SessionKeyHeaders(keyId, sessionKey)));
        }
        return true;
    }

    private String requiredHeader(HttpHeaders headers, String name) {
        var values = headers.get(name);
        if (values == null || values.size() != 1 || values.get(0).isBlank()) {
            throw new InvalidCryptoRequestException(name + " must have exactly one non-blank value.");
        }
        return values.get(0);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception exception) {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }
}
