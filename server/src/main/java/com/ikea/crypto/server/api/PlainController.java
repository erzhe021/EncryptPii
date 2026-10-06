package com.ikea.crypto.server.api;

import com.ikea.crypto.server.model.DemoPlainRequest;
import com.ikea.crypto.server.model.DemoPlainResponse;
import com.ikea.crypto.server.model.Result;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/plain/server")
public class PlainController {

    @PostMapping("/normal")
    public Result<DemoPlainResponse> normal(@RequestBody DemoPlainRequest request) {
        return Result.ok(new DemoPlainResponse("123456789012", 3, 10000L, "remarks for request: " + request.data()));
    }

}
