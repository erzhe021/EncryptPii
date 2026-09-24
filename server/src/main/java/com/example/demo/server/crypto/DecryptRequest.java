package com.example.demo.server.crypto;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to indicate that the request body should be decrypted using the specified cryptographic algorithm.
 * This annotation can be applied to methods or classes in a Spring Boot application.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface DecryptRequest {
    CryptoAlgorithm value() default CryptoAlgorithm.RSA;
}
