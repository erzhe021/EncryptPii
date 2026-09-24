package com.example.demo.crypto.rsa;

public record RsaCipherPayload(
        //aes key encrypted with rsa
        String encryptedAesKeyBase64,

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64
) {
}
