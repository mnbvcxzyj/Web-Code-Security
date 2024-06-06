package com.wcsp.web_code_security_project.controller;

import com.wcsp.web_code_security_project.DigitalEnvelopeManager;
import com.wcsp.web_code_security_project.KeyManager;
import com.wcsp.web_code_security_project.domain.Contract;
import com.wcsp.web_code_security_project.domain.DigitalEnvelope;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

@RestController
public class IdolController {
    private final KeyManager keyManager = new KeyManager();
    private final DigitalEnvelopeManager envelopeManager = new DigitalEnvelopeManager();
    private SecretKey secretKey;

    public IdolController() throws Exception {
        this.secretKey = keyManager.createSymmetricKey();
        keyManager.saveSecretKey("secret.key", secretKey);
    }

    // 키 생성
    @PostMapping("/keys")
    @ResponseBody
    public String generateKeys(@RequestParam String keyName) throws Exception {
        KeyPair keyPair = keyManager.createAsymmetricKeyPair();
        keyManager.saveAsymmetricKeyPair(keyName + "_public.key", keyName + "_private.key", keyPair);
        return "성공적으로 저장하였습니다!";
    }

    @GetMapping("/form")
    public String showCreateContractForm(Model model) {
        model.addAttribute("contract", new Contract());
        return "/form/";
    }

//    @PostMapping("/sign")
//    @ResponseBody
//    public String signDocument(@RequestParam String document, @RequestParam String signature) throws Exception {
//        KeyPair keyPair = keyManager.readAsymmetricKeyPair("publicKey.key", "privateKey.key");
//        DigitalEnvelope envelope = envelopeManager.createDigitalEnvelope("document", document, keyPair.getPrivate(), keyPair.getPublic());
//        envelopeManager.saveEnvelopeToFile(envelope, "document");
//        return "전자 서명 생성";
//    }

//    @PostMapping("/verify")
//    @ResponseBody
//    public String verifyDocument(@RequestParam String document, @RequestParam String signature) throws Exception {
//        DigitalEnvelope envelope = envelopeManager.loadEnvelopeFromFile("document");
//        boolean isValid = envelopeManager.verifyEnvelope(envelope, document);
//        return isValid ? "ㅇㅋ." : "ㄴㄴ.";
//    }



    @PostMapping("/sign")
    public String signContract(@RequestParam String contractTitle, @RequestParam String signature) throws GeneralSecurityException, IOException {
//        Contract contract = loadContractFromFile(contractTitle);

        // 키 생성
        KeyPair keyPair = keyManager.createAsymmetricKeyPair();
        keyManager.saveAsymmetricKeyPair("publicKey_" + contractTitle + ".key", "privateKey_" + contractTitle + ".key", keyPair);

        // 전자봉투 생성
//        DigitalEnvelope envelope = envelopeManager.createDigitalEnvelope(contractTitle, contract.getContent(), keyPair.getPrivate(), keyPair.getPublic());

        // 전자봉투 저장
//        envelopeManager.saveEnvelopeToFile(envelope, contractTitle);

        return "redirect:/contracts";
    }


}
