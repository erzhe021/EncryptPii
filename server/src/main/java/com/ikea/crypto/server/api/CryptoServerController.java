package com.ikea.crypto.server.api;

import com.ikea.crypto.server.model.DemoPlainRequest;
import com.ikea.crypto.server.model.DemoPlainResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/plain/server")
public class CryptoServerController {

    @PostMapping("/normal")
    public DemoPlainResponse normal(@RequestBody DemoPlainRequest request) {
        return new DemoPlainResponse("123456789012", 3, 10000L, "remarks");
    }

}
