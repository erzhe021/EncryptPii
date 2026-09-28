package com.ikea.crypto.common.model.demo;

import jakarta.validation.constraints.NotBlank;

/**
 * SensitiveData is a record that represents sensitive data.
 *
 * @param data the sensitive data
 */
public record SensitiveData(
        @NotBlank(message = "sensitive data is required")
        String data
) {
}
