package com.example.demo.client;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.ecdh.EcdhHttpCryptoClient;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaCryptoClient;
import com.example.demo.crypto.rsa.RsaHttpCryptoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/crypto/client")
public class CryptoClientController {

    private final URI serverBaseUri;

    public CryptoClientController(@Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl) {
        this.serverBaseUri = URI.create(serverBaseUrl);
    }

    @PostMapping("/rsa")
    public Map<String, Object> rsaEncrypt(@RequestBody(required = false) Map<String, String> payload) throws Exception {
        String data = payload == null || payload.get("data") == null ? "{\"data\":\"Hello, World!\"}" : payload.get("data");
        RsaHttpCryptoClient httpClient = new RsaHttpCryptoClient(serverBaseUri);
        RsaCryptoClient cryptoClient = new RsaCryptoClient(httpClient);
        RsaCipherPayload encrypted = cryptoClient.encrypt(data);
        String decrypted = cryptoClient.decrypt(encrypted);

        return Map.of(
                "algorithm", CryptoConstants.ALGORITHM_RSA,
                "encrypted", encrypted,
                "decrypted", decrypted
        );
    }

    @PostMapping("/ecdh")
    public Map<String, Object> ecdhEncrypt(@RequestBody(required = false) Map<String, String> payload) throws Exception {
        String data = payload == null || payload.get("data") == null ? "{\"data\":\"Hello, World!\"}" : payload.get("data");
        EcdhHttpCryptoClient httpClient = new EcdhHttpCryptoClient(serverBaseUri);
        EcdhCryptoClient cryptoClient = new EcdhCryptoClient(httpClient);
        EcdhCipherPayload encrypted = cryptoClient.encrypt(data);
        String decrypted = cryptoClient.decrypt(encrypted);

        return Map.of(
                "algorithm", CryptoConstants.ALGORITHM_ECDH,
                "encrypted", encrypted,
                "decrypted", decrypted
        );
    }
}
