package com.example.demo.crypto.rsa;

import com.example.demo.crypto.AesCipherPayload;

public record RsaCipherPayload(
        //session key encrypted with rsa
        String encryptedSessionKeyBase64,

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64
) implements AesCipherPayload {
}
