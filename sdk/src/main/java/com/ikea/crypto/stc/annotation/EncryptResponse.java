package com.ikea.crypto.stc.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to indicate that the response body of a method or class should be encrypted.
 * Only applies when the client explicitly sends X-STC-Enabled: true.
 * <p>
 * This annotation can be applied to methods or classes to specify that the outgoing response body
 * should be encrypted before sending it to the client. It is typically used in conjunction with an
 * encryption mechanism that handles the encryption logic based on the specified configuration.
 * </p>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptResponse {
}
