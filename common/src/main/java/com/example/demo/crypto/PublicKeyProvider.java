package com.example.demo.crypto;

import java.security.GeneralSecurityException;

public interface PublicKeyProvider {
    Object fetchServerPublicKey() throws GeneralSecurityException;
}
