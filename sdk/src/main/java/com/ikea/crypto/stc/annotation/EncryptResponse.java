package com.ikea.crypto.stc.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to indicate that the response body should be encrypted using ECDH.
 * This annotation can be applied to methods or classes in a Spring Boot application.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptResponse {
}
