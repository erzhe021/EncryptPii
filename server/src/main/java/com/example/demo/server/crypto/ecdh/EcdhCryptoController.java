package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SensitiveData;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.DecryptRequest;
import com.example.demo.server.crypto.EncryptResponse;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

@RestController
public class EcdhCryptoController {

    private final EcdhCryptoService ecdhCryptoService;

    public EcdhCryptoController(EcdhCryptoService ecdhCryptoService) {
        this.ecdhCryptoService = ecdhCryptoService;
    }

    @GetMapping("/crypto/server/ecdh/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return ecdhCryptoService.getPublicKey();
    }

    @PostMapping("/crypto/server/ecdh/bidirectional")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public SensitiveData bidirectionalECDHEncrypt(@RequestBody SensitiveData request) {
        return new SensitiveData("mock ecdh response for request - " + request.data());
    }

    @PostMapping("/crypto/server/ecdh/request-only")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    public PlainData requestOnlyEcdhEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/crypto/server/ecdh/response-only")
    public Map<String, String> responseOnlyEcdhEncrypt(
            @RequestBody java.util.Map<String, String> request,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_KEY, required = false) String sessionKeyBase64,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_IV, required = false) String sessionIvBase64
    ) throws GeneralSecurityException {
        String data = request == null || request.get("data") == null ? "Hello, World!" : request.get("data");
        String responseData = "mock ecdh response for request - " + data;
        if (sessionKeyBase64 == null || sessionKeyBase64.isBlank()) {
            throw new IllegalArgumentException("client session key is required for response-only ECDH encryption");
        }
        if (sessionIvBase64 == null || sessionIvBase64.isBlank()) {
            throw new IllegalArgumentException("client session IV is required for response-only ECDH encryption");
        }

        SecretKey sessionKey = new SecretKeySpec(EncodingUtils.fromBase64(sessionKeyBase64), CryptoConstants.ALGORITHM_AES);
        byte[] iv = EncodingUtils.fromBase64(sessionIvBase64);

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        byte[] encryptedData = aesCipher.doFinal(responseData.getBytes(StandardCharsets.UTF_8));

        return java.util.Map.of(
                "ivBase64", sessionIvBase64,
                "encryptedDataBase64", EncodingUtils.toBase64(encryptedData)
        );
    }

}
