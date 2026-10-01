package com.ikea.crypto.server.api;

import com.ikea.crypto.server.model.DemoPlainResponse;
import com.ikea.crypto.server.model.DemoSensitiveRequest;
import com.ikea.crypto.server.model.DemoSensitiveResponse;
import com.ikea.crypto.server.model.PlainRequestPayload;
import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crypto/server/ecdh")
@Slf4j
public class CryptoServerController {

    @PostMapping("/bidirectional")
    @DecryptRequest
    @EncryptResponse
    public DemoSensitiveResponse bidirectionalECDHEncrypt(@Valid @RequestBody DemoSensitiveRequest request) {
        log.debug("【api called】start to processing bidirectional ECDH encryption");
        return new DemoSensitiveResponse(
                request.name(),
                request.phone(),
                request.email(),
                request.address(),
                "bidirectional ecdh encryption"
        );
    }

    @PostMapping("/request-only")
    @DecryptRequest
    public DemoPlainResponse requestOnlyEcdhEncrypt(@Valid @RequestBody DemoSensitiveRequest request) {
        log.debug("【api called】start to processing request-only ECDH encryption");
        return new DemoPlainResponse(
                request.name(),
                "123456789",
                1,
                10000L,
                "request-only ecdh encryption");
    }

    @PostMapping("/response-only")
    @EncryptResponse
    public DemoSensitiveResponse responseOnlyEcdhEncrypt(@Valid @RequestBody PlainRequestPayload request) {
        log.debug("【api called】start to processing response-only ECDH encryption");
        CryptoSessionContextAccessor.setCryptoSessionContext(
                new CryptoSessionContext(request.handshakeContext())
        );
        return new DemoSensitiveResponse(
                "eric",
                "13764641531",
                "eric.zheng@ingka.ikea.com",
                "上海市长宁区荟聚中心办公A楼",
                "response-only ecdh encryption, request request: " + request.request().data()
        );
    }

}
