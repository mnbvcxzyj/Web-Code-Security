package com.wcsp.web_code_security_project.domain;

import lombok.Getter;

import java.io.Serializable;
import java.time.LocalDate;

@Getter
public final class Contract implements Serializable {
   private final String name;
   private final String publicKeyFile;
   private final String privateKeyFile;
   private final String document;
   private final LocalDate startDate;
   private final LocalDate endDate;
   private final String signFile;
   private final String originFile;

   public Contract(String name, String publicKeyFile, String privateKeyFile, String document, LocalDate startDate, LocalDate endDate, String signFile, String originFile) {
      this.name = name;
      this.publicKeyFile = publicKeyFile;
      this.privateKeyFile = privateKeyFile;
      this.document = document;
      this.startDate = startDate;
      this.endDate = endDate;
      this.signFile = signFile;
      this.originFile = originFile;
   }
}
