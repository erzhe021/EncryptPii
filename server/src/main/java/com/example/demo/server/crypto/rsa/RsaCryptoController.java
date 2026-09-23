package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SensitiveData;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.DecryptRequest;
import com.example.demo.server.crypto.EncryptResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

@RestController
public class RsaCryptoController {

    private final RsaCryptoService rsaCryptoService;

    public RsaCryptoController(RsaCryptoService rsaCryptoService) {
        this.rsaCryptoService = rsaCryptoService;
    }

    @GetMapping("/crypto/server/rsa/public-key")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoService.getPublicKey();
    }

    @PostMapping("/crypto/server/rsa/bidirectional")
    @DecryptRequest(CryptoAlgorithm.RSA)
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveData bidirectionalRsaEncrypt(@RequestBody SensitiveData request) {
        return new SensitiveData("mock rsa response for request - " + request.data());
    }

    @PostMapping("/crypto/server/rsa/request-only")
    @DecryptRequest(CryptoAlgorithm.RSA)
    public PlainData requestOnlyRsaEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/crypto/server/rsa/response-only")
    public RsaCipherPayload responseOnlyRsaEncrypt(@RequestBody Map<String, String> request) throws GeneralSecurityException {
        String data = request == null || request.get("data") == null ? "Hello, World!" : request.get("data");
        String responseData = "mock rsa response for request - " + data;
        String clientPublicKeyBase64 = request.get("clientPublicKeyBase64");
        if (clientPublicKeyBase64 == null || clientPublicKeyBase64.isBlank()) {
            throw new IllegalArgumentException("clientPublicKeyBase64 is required for response-only RSA encryption");
        }

        PublicKey clientPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(clientPublicKeyBase64))
        );

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, new SecureRandom());
        SecretKey aesKey = keyGenerator.generateKey();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        byte[] encryptedData = aesCipher.doFinal(responseData.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return new RsaCipherPayload(
                EncodingUtils.toBase64(encryptedAesKey),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

}
