package com.wcsp.web_code_security_project.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.PublicKey;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class DigitalEnvelope {
    private String data;
    private byte[] signature;
    private PublicKey publicKey;
}
