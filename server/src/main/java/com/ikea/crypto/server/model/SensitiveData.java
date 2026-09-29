package com.ikea.crypto.server.model;

import jakarta.validation.constraints.NotBlank;

public record SensitiveData(
        @NotBlank(message = "sensitive data is required")
        String data
) {
}
