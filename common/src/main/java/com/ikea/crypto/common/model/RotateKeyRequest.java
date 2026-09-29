package com.ikea.crypto.common.model;

public record RotateKeyRequest(String keyAlias, boolean force) {
    public RotateKeyRequest(String keyAlias) {
        this(keyAlias, false);
    }
}

