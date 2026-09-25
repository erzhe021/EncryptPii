package com.ikea.crypto.server.advice;

import com.ikea.crypto.server.model.CryptoAlgorithm;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to indicate that the response body should be encrypted using the specified cryptographic algorithm.
 * This annotation can be applied to methods or classes in a Spring Boot application.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptResponse {
    CryptoAlgorithm value() default CryptoAlgorithm.RSA;
}
