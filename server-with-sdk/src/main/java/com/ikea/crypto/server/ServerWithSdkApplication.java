package com.ikea.crypto.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"com.ikea.crypto.server"})
public class ServerWithSdkApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServerWithSdkApplication.class, args);
    }
}
