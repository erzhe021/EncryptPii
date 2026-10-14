package com.ikea.crypto.stc.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to indicate that the request body of a method or class should be decrypted.
 * <p>
 * This annotation can be applied to methods or classes to specify that the incoming request body
 * should be decrypted before processing. It is typically used in conjunction with a decryption
 * mechanism that handles the decryption logic based on the specified configuration.
 * </p>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface DecryptRequest {
}
