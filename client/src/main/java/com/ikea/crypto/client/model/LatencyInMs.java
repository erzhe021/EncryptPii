package com.ikea.crypto.client.model;

public record LatencyInMs(long total, long encryption, long http, long decryption) {
}
