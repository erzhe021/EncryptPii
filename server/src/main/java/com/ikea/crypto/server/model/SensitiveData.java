package com.ikea.crypto.server.model;

import jakarta.validation.constraints.NotBlank;

/**
 * SensitiveData is a record that represents sensitive request.
 *
 * @param data the sensitive request
 */
public record SensitiveData(
        @NotBlank(message = "sensitive request is required")
        String data
) {
}
