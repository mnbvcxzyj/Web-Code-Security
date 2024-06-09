package com.wcsp.web_code_security_project.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDate;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class Contract implements Serializable {
    private String name;
    private String address;
    private String publicKeyFile;
    private String privateKeyFile;
    private String document;
    private LocalDate startDate;
    private LocalDate endDate;
    private String signFile;
    private String originFile;

}
