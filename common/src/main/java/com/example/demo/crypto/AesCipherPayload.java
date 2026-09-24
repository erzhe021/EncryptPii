package com.example.demo.crypto;

public interface AesCipherPayload {
    String ivBase64();

    String encryptedDataBase64();
}
