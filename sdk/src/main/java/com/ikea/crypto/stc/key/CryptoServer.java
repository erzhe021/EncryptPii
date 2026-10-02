package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.model.*;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;

@Slf4j
public class CryptoServer {

    public static final Duration DEFAULT_TICKET_TTL = HandshakeService.DEFAULT_TICKET_TTL;

    private final HandshakeService handshakeService;
    private final EcdsaSigningService ecdsaSigningService;
    private final AesTicketMasterService aesTicketMasterService;

    public CryptoServer(PrivateKey ecdsaPrivateKey, PublicKey ecdsaPublicKey, SecretKey ticketMasterKey) {
        this(new EcdsaSigningService(ecdsaPrivateKey, ecdsaPublicKey), new AesTicketMasterService(ticketMasterKey), DEFAULT_TICKET_TTL);
    }

    public CryptoServer(EcdsaSigningService ecdsaSigningService, AesTicketMasterService aesTicketMasterService) {
        this(ecdsaSigningService, aesTicketMasterService, DEFAULT_TICKET_TTL);
    }

    public CryptoServer(EcdsaSigningService ecdsaSigningService, AesTicketMasterService aesTicketMasterService, Duration ticketTtl) {
        if (ecdsaSigningService == null || ecdsaSigningService.getPrivateKey() == null || ecdsaSigningService.getPublicKey() == null) {
            throw new IllegalArgumentException("ECDSA signing service is required.");
        }
        if (aesTicketMasterService == null || aesTicketMasterService.getTicketMasterKey() == null) {
            throw new IllegalArgumentException("Ticket master service is required for stateless ephemeral key encryption.");
        }
        this.ecdsaSigningService = ecdsaSigningService;
        this.aesTicketMasterService = aesTicketMasterService;
        this.handshakeService = new HandshakeService(ecdsaSigningService, aesTicketMasterService, ticketTtl);
    }

    public static CryptoServer createFromVault(VaultProperties properties)
            throws GeneralSecurityException, IOException, InterruptedException {
        return createFromVault(
                properties.getAddr(),
                properties.getToken(),
                properties.getEcdsaSecretPath(),
                properties.getAesSecretPath(),
                properties.getAuthMethod()
        );
    }

    private static CryptoServer createFromVault(
            String vaultAddr,
            String vaultToken,
            String ecdsaSecretPath,
            String aesSecretPath,
            VaultProperties.AuthMethod authMethod
    ) throws GeneralSecurityException, IOException, InterruptedException {
        VaultProperties properties = new VaultProperties();
        properties.setAddr(vaultAddr);
        properties.setToken(vaultToken);
        properties.setAuthMethod(authMethod);
        properties.setEcdsaSecretPath(normalizeSecretPath(ecdsaSecretPath));
        properties.setAesSecretPath(normalizeSecretPath(aesSecretPath));

        EcdsaSigningService ecdsaSigningService = EcdsaSigningService.fromVault(properties);
        AesTicketMasterService aesTicketMasterService = AesTicketMasterService.fromVault(properties);
        return new CryptoServer(ecdsaSigningService, aesTicketMasterService);
    }

    public VerificationKeyResponse getEcdsaPublicKey() {
        return handshakeService.getEcdsaPublicKey();
    }

    public EphemeralKeyResponse getEphemeralPublicKey() throws GeneralSecurityException {
        return handshakeService.getEphemeralPublicKey();
    }

    public String decrypt(CipherRequestPayload payload) throws GeneralSecurityException {
        return handshakeService.decrypt(payload);
    }

    public CipherDataPayload encryptWithHandshakeContext(String data, HandshakeContext handshakeContext) throws GeneralSecurityException {
        return handshakeService.encryptWithHandshakeContext(data, handshakeContext);
    }

    public void validatePayload(CipherRequestPayload payload) {
        handshakeService.validatePayload(payload);
    }

    private static String normalizeSecretPath(String secretPath) {
        if (secretPath == null || secretPath.isBlank()) {
            return "sensitive-transport-crypto/ecdsa-ciam";
        }
        String normalized = secretPath.trim();
        return normalized.startsWith("/") ? normalized.substring(1) : normalized;
    }

}
