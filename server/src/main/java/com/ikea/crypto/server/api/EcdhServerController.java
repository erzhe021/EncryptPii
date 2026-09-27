package com.ikea.crypto.server.api;

import com.ikea.crypto.common.PlainData;
import com.ikea.crypto.common.SensitiveData;
import com.ikea.crypto.common.ecdh.EcdhEphemeralKeyResponse;
import com.ikea.crypto.common.ecdh.EcdhPlainPayload;
import com.ikea.crypto.common.ecdh.EcdsaVerificationKeyResponse;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.service.EcdhCryptoServer;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/crypto/server/ecdh")
@Slf4j
public class EcdhServerController {

    private final EcdhCryptoServer cryptoServer;

    public EcdhServerController(EcdhCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/ephemeral-public-key")
    public EcdhEphemeralKeyResponse getEcdhEphemeralPublicKey() throws GeneralSecurityException {
        log.debug("【api called】start to generating ECDH ephemeral key pair and return public key");
        return cryptoServer.getEphemeralPublicKey();
    }

    @GetMapping("/ecdsa-public-key")
    public EcdsaVerificationKeyResponse getEcdsaPublicKey() {
        log.debug("【api called】start to retrieving ECDSA public key for signature verification");
        return cryptoServer.getEcdsaPublicKey();
    }

    @PostMapping("/bidirectional")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public SensitiveData bidirectionalECDHEncrypt(@Valid @RequestBody SensitiveData request) {
        log.debug("【api called】start to processing bidirectional ECDH encryption");
        return new SensitiveData("mock ecdh response for request - " + request.data());
    }

    @PostMapping("/request-only")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    public PlainData requestOnlyEcdhEncrypt(@Valid @RequestBody SensitiveData request) {
        log.debug("【api called】start to processing request-only ECDH encryption");
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/response-only")
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public PlainData responseOnlyEcdhEncrypt(@Valid @RequestBody EcdhPlainPayload request) {
        log.debug("【api called】start to processing response-only ECDH encryption");
        CryptoSessionContextAccessor.setCryptoSessionContext(
                CryptoSessionContext.ecdhResponseOnly(request.handshakeContext())
        );
        return new PlainData("mock ecdh response for request - " + request.data());
    }

}
