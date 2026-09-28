package com.ikea.crypto.server.api;

import com.ikea.crypto.common.model.demo.PlainData;
import com.ikea.crypto.common.model.demo.SensitiveData;
import com.ikea.crypto.common.model.EphemeralKeyResponse;
import com.ikea.crypto.common.model.PlainRequestPayload;
import com.ikea.crypto.common.model.VerificationKeyResponse;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.service.CryptoServer;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/crypto/server/ecdh")
@Slf4j
public class CryptoServerController {

    private final CryptoServer cryptoServer;

    public CryptoServerController(CryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/ephemeral-public-key")
    public EphemeralKeyResponse getEcdhEphemeralPublicKey() throws GeneralSecurityException {
        log.debug("【api called】start to generating ECDH ephemeral key pair and return public key");
        return cryptoServer.getEphemeralPublicKey();
    }

    @GetMapping("/ecdsa-public-key")
    public VerificationKeyResponse getEcdsaPublicKey() {
        log.debug("【api called】start to retrieving ECDSA public key for signature verification");
        return cryptoServer.getEcdsaPublicKey();
    }

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
