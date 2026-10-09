package com.ikea.crypto.server.api;

import com.ikea.crypto.server.exception.BusinessException;
import com.ikea.crypto.server.exception.SystemException;
import com.ikea.crypto.server.model.*;
import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crypto/server")
public class CryptoController {

    @PostMapping("/bidirectional")
    @DecryptRequest
    @EncryptResponse
    public Result<DemoSensitiveResponse> bidirectional(@RequestBody DemoSensitiveRequest request) {
        return Result.ok(new DemoSensitiveResponse(
                request.name(),
                request.phone(),
                request.email(),
                request.address(),
                "bidirectional crypto")
        );
    }

    @PostMapping("/request-only")
    @DecryptRequest
    public Result<DemoPlainResponse> requestOnly(@RequestBody DemoSensitiveRequest request) {
        return Result.ok(new DemoPlainResponse(
                request.name(),
                "1234-5678-9012-3456",
                3,
                1500L,
                "request-only crypto")
        );
    }

    @PostMapping("/response-only")
    @EncryptResponse
    public Result<DemoSensitiveResponse> responseOnly(@RequestBody(required = false) DemoPlainRequest request) {
        return Result.ok(new DemoSensitiveResponse(
                "张三",
                "11111111111",
                "zhangsan@example.com",
                "上海市长宁区某某广场办公A楼",
                "response-only crypto for request: " + request.data()));
    }

    @PostMapping("/response-only/client-exception")
    @EncryptResponse
    public Result<DemoSensitiveResponse> responseOnlyClientException(@RequestBody(required = false) DemoPlainRequest request) {
        throw new IllegalArgumentException("Demo 4xx exception with sensitive info e.g. mobile: 11111111111");
    }

    @PostMapping("/response-only/system-exception")
    @EncryptResponse
    public Result<DemoSensitiveResponse> responseOnlySystemException(@RequestBody(required = false) DemoPlainRequest request) {
        throw new SystemException("Demo 5xx exception with sensitive info e.g. mobile: 11111111111");
    }

    @PostMapping("/response-only/business-exception")
    @EncryptResponse
    public Result<DemoSensitiveResponse> responseOnlyBizException(@RequestBody(required = false) DemoPlainRequest request) {
        throw new BusinessException("code-123", "Demo business exception with sensitive info e.g. mobile: 11111111111");
    }

}
