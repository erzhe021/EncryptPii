package com.ikea.crypto.server.model;

public record DemoPlainResponse(String cardNumber, int memberTier, long points, String remarks) {
}
