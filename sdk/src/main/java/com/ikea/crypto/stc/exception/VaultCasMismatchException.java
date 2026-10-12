package com.ikea.crypto.stc.exception;

import lombok.Getter;

/**
 * Thrown when Vault KV v2 Check-And-Set (CAS) validation fails, indicating another pod
 * has concurrently updated the secret.
 */
public class VaultCasMismatchException extends RuntimeException {

    @Getter
    private final int expectedCas;

    public VaultCasMismatchException(String message, int expectedCas) {
        super(message);
        this.expectedCas = expectedCas;
    }

    public VaultCasMismatchException(String message, int expectedCas, Throwable cause) {
        super(message, cause);
        this.expectedCas = expectedCas;
    }
}
