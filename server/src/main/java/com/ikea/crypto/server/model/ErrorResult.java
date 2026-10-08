package com.ikea.crypto.server.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResult {

    private Long timestamp;

    private Integer status;

    private String error;

    private String message;

    private String path;
}
