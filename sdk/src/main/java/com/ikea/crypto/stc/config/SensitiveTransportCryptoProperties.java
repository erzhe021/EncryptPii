package com.ikea.crypto.stc.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "sensitive.transport.crypto")
public class SensitiveTransportCryptoProperties {

    private boolean enabled = true;

    private EndpointProperties endpoint = new EndpointProperties();

    private ExceptionHandlerProperties exceptionHandler = new ExceptionHandlerProperties();

    @Data
    public static class EndpointProperties {
        private boolean enabled = true;
        private String basePath = "/crypto/server/ecdh";
    }

    @Data
    public static class ExceptionHandlerProperties {
        private boolean enabled = true;
    }
}
