package com.ikea.crypto.stc.model;

public record RotateKeyRequest(String keyAlias, boolean force) {
    public RotateKeyRequest(String keyAlias) {
        this(keyAlias, false);
    }
}

