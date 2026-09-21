package com.example.demo.crypto;

import java.security.GeneralSecurityException;

public interface PublicKeyProvider {
    PublicKeyResponse fetchServerPublicKey() throws GeneralSecurityException;
}
