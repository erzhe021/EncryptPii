package com.example.demo.server.crypto;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.annotation.Annotation;

public final class CryptoAdviceSupport {
    private CryptoAdviceSupport() {
    }

    public static <A extends Annotation> A findAnnotation(MethodParameter methodParameter, Class<A> annotationType) {
        A annotation = methodParameter.getMethodAnnotation(annotationType);
        if (annotation != null) {
            return annotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(methodParameter.getContainingClass(), annotationType);
    }

    public static CryptoSessionContext<?> getSessionContext() {
        return CryptoSessionContextAccessor.getCryptoSessionContext();
    }
}
