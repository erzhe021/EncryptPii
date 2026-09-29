package com.ikea.crypto.common.model.payload;

public record RotateKeyRequest(String keyAlias, Boolean force) {
}
