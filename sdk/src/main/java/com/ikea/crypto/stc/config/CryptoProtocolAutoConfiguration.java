package com.ikea.crypto.stc.config;

import com.ikea.crypto.stc.web.CryptoRequestInterceptor;
import com.ikea.crypto.stc.web.advice.CryptoExceptionHandler;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(WebMvcConfigurer.class)
public class CryptoProtocolAutoConfiguration {

    @Bean
    public WebMvcConfigurer cryptoProtocolConfigurer(Environment environment,
                                                    ObjectProvider<CryptoPayloadHandler> payloadHandler) {
        boolean enabled = environment.getProperty("sensitive.transport.crypto.enabled", Boolean.class, false);
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(new CryptoRequestInterceptor(enabled, payloadHandler));
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoExceptionHandler cryptoExceptionHandler() {
        return new CryptoExceptionHandler();
    }
}
