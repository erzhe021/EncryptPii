package com.ikea.crypto.client.api;

import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.client.model.DemoPlainRequest;
import com.ikea.crypto.client.model.DemoPlainResponse;
import com.ikea.crypto.client.model.LatencyInMs;
import com.ikea.crypto.client.model.Result;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/plain/client")
public class PlainClientController {

    private final CryptoHttpClient cryptoHttpClient;
    private final String normalPath;

    public PlainClientController(
            @Value("${plain.server.base-url}") String kongBaseUrl,
            @Value("${plain.server.endpoints.normal}") String normalPath) {
        this.cryptoHttpClient = new CryptoHttpClient(URI.create(kongBaseUrl));
        this.normalPath = normalPath;
    }

    @PostMapping("/normal")
    public Map<String, Object> normal(@RequestBody DemoPlainRequest request) throws Exception {
        long startTime = System.currentTimeMillis();
        Result<DemoPlainResponse> response = cryptoHttpClient.postPlain(normalPath, request);
        long finish = System.currentTimeMillis();
        return Map.of(
                "request", request,
                "response", response,
                "latency in ms", new LatencyInMs(
                        finish - startTime, 0, finish - startTime, 0)
        );
    }
}
