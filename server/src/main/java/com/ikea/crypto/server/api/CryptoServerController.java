package com.ikea.crypto.server.api;

import com.ikea.crypto.server.model.PlainData;
import com.ikea.crypto.server.model.SensitiveData;
import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import com.ikea.crypto.stc.model.PlainRequestPayload;
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
    public SensitiveData bidirectionalECDHEncrypt(@Valid @RequestBody SensitiveData request) {
        log.debug("【api called】start to processing bidirectional ECDH encryption");
        return new SensitiveData("mock ecdh response for request - " + request.data());
    }

    @PostMapping("/request-only")
    @DecryptRequest
    public PlainData requestOnlyEcdhEncrypt(@Valid @RequestBody SensitiveData request) {
        log.debug("【api called】start to processing request-only ECDH encryption");
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/response-only")
    @EncryptResponse
    public PlainData responseOnlyEcdhEncrypt(@Valid @RequestBody PlainRequestPayload request) {
        log.debug("【api called】start to processing response-only ECDH encryption");
        CryptoSessionContextAccessor.setCryptoSessionContext(
                new CryptoSessionContext(request.handshakeContext())
        );
        return new PlainData("mock ecdh response for request - " + request.data());
    }

}
