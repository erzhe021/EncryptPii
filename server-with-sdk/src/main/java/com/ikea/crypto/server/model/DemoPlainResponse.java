package com.ikea.crypto.server.model;

public record DemoPlainResponse(String name, String cardNumber, int memberTier, long points, String remarks) {
}
