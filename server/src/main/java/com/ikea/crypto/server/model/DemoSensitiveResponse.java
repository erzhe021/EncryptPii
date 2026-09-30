package com.ikea.crypto.server.model;

public record DemoSensitiveResponse(String name, String phone, String email, String address, String extraInfo) {

    public DemoSensitiveResponse(DemoSensitiveRequest demoSensitiveRequest, String extraInfo) {
        this(demoSensitiveRequest.name(), demoSensitiveRequest.phone(), demoSensitiveRequest.email(), demoSensitiveRequest.address(), extraInfo);
    }
}
