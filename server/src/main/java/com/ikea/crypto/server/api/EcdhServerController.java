package com.ikea.crypto.server.api;

import com.ikea.crypto.common.PlainData;
import com.ikea.crypto.common.SensitiveData;
import com.ikea.crypto.common.ecdh.EcdhPublicKeyResponse;
import com.ikea.crypto.common.ecdh.EcdhResponseOnlyRequest;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.service.EcdhCryptoServer;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/crypto/server/ecdh")
public class EcdhServerController {

    private final EcdhCryptoServer cryptoServer;

    public EcdhServerController(EcdhCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return cryptoServer.generateEphemeralEcdhPublicKey();
    }

    @PostMapping("/bidirectional")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public SensitiveData bidirectionalECDHEncrypt(@Valid @RequestBody SensitiveData request) {
        return new SensitiveData("mock ecdh response for request - " + request.data());
    }

    @PostMapping("/request-only")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    public PlainData requestOnlyEcdhEncrypt(@Valid @RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/response-only")
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public PlainData responseOnlyEcdhEncrypt(@Valid @RequestBody EcdhResponseOnlyRequest request) {
        CryptoSessionContextAccessor.setCryptoSessionContext(
                CryptoSessionContext.ecdhResponseOnly(request.toHandshakeContext())
        );
        return new PlainData("mock ecdh response for request - " + request.data());
    }

}
