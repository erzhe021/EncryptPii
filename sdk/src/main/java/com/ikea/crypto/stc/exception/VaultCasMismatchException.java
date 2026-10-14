package com.ikea.crypto.stc.exception;

import lombok.Getter;

import java.io.Serial;

/**
 * Thrown when a Vault operation fails due to a CAS (Check-And-Set) mismatch.
 * This indicates that the expected version of the data does not match the actual version in the Vault,
 * which can occur in concurrent modification scenarios.
 */
public class VaultCasMismatchException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

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
