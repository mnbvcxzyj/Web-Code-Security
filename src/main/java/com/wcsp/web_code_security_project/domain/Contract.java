package com.wcsp.web_code_security_project.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class Contract {
    private String name;
    private String address;
    private LocalDate startDate;
    private LocalDate endDate;
    private String status;
}
