package com.ikea.crypto.stc.web;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

import java.util.List;

public final class CryptoRequestMode {
    private static final String ENABLED_ATTRIBUTE = CryptoRequestMode.class.getName() + ".enabled";

    private CryptoRequestMode() {
    }

    public static boolean parse(HttpHeaders headers) {
        List<String> values = headers.get(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENABLED);
        boolean enabled = false;
        if (values != null) {
            if (values.size() != 1
                    || (!"true".equalsIgnoreCase(values.get(0)) && !"false".equalsIgnoreCase(values.get(0)))) {
                throw new InvalidCryptoRequestException("X-STC-Enabled must be a single true or false value.");
            }
            enabled = Boolean.parseBoolean(values.get(0));
        }
        if (!enabled && (headers.containsKey(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID)
                || headers.containsKey(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY))) {
            throw new InvalidCryptoRequestException("Session key headers require X-STC-Enabled: true.");
        }
        return enabled;
    }

    public static void setEnabled(HttpServletRequest request, boolean enabled) {
        request.setAttribute(ENABLED_ATTRIBUTE, enabled);
    }

    public static boolean isEnabled(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(ENABLED_ATTRIBUTE));
    }
}
