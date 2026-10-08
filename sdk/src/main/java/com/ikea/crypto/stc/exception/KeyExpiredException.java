package com.ikea.crypto.stc.exception;

import com.ikea.crypto.stc.model.PublicKeyResponse;

public class KeyExpiredException extends CryptoClientSideException {
    private final PublicKeyResponse latestKey;

    public KeyExpiredException(PublicKeyResponse latestKey) {
        super("The key version has expired");
        this.latestKey = latestKey;
    }

    public PublicKeyResponse latestKey() {
        return latestKey;
    }
}
