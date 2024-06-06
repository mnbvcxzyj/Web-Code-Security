package com.wcsp.web_code_security_project.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.security.PublicKey;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class DigitalEnvelope implements Serializable {
    private String data;
    private byte[] signature;
    private PublicKey publicKey;
}
