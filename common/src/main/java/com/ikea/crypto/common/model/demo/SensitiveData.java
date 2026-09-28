package com.ikea.crypto.common.model.demo;

import jakarta.validation.constraints.NotBlank;

public record SensitiveData(
        @NotBlank(message = "sensitive data is required")
        String data
) {
}
