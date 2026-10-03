package com.ikea.crypto.client.api;

import com.ikea.crypto.client.model.DemoPlainRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

@RestController
@RequestMapping("/plain/client")
public class PlainClientController {

    private final RestClient restClient;
    private final String normalPath;

    public PlainClientController(
            RestClient.Builder builder,
            @Value("${plain.server.base-url}") String kongBaseUrl,
            @Value("${plain.server.endpoints.normal}") String normalPath) {
        this.restClient = builder.baseUrl(kongBaseUrl).build();
        this.normalPath = normalPath;
    }

    @PostMapping("/normal")
    public ResponseEntity<byte[]> normal(@RequestBody DemoPlainRequest request) {
        return forward(normalPath, request);
    }

    private ResponseEntity<byte[]> forward(String path, Object body) {
        RestClient.RequestBodySpec request = restClient.post().uri(path).contentType(MediaType.APPLICATION_JSON);
        if (body != null) {
            request.body(body);
        }
        return request.exchange((httpRequest, response) -> {
            ResponseEntity.BodyBuilder result = ResponseEntity.status(response.getStatusCode());
            MediaType contentType = response.getHeaders().getContentType();
            if (contentType != null) {
                result.contentType(contentType);
            }
            return result.body(response.getBody().readAllBytes());
        });
    }
}
