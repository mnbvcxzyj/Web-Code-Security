package com.wcsp.web_code_security_project.controller;

import com.wcsp.web_code_security_project.DigitalEnvelopeManager;
import com.wcsp.web_code_security_project.KeyManager;
import com.wcsp.web_code_security_project.domain.Contract;
import com.wcsp.web_code_security_project.domain.DigitalEnvelope;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.crypto.SecretKey;
import java.security.KeyPair;

@RestController
public class IdolController {
    private final KeyManager keyManager = new KeyManager();
    private final DigitalEnvelopeManager envelopeManager = new DigitalEnvelopeManager();

    public IdolController() throws Exception {
        SecretKey secretKey = keyManager.createSymmetricKey();
        keyManager.saveSecretKey("secret.key", secretKey);
    }

    // 키 생성
    @PostMapping("/keys")
    @ResponseBody
    public void generateKeys(@RequestParam String keyName) throws Exception {
        KeyPair keyPair = keyManager.createAsymmetricKeyPair();
        keyManager.saveAsymmetricKeyPair(keyName + "_public.key", keyName + "_private.key", keyPair);
    }

    // 계약서 작성 및 전자 서명
    @PostMapping("/sign")
    @ResponseBody
    public ModelAndView signDocument(@ModelAttribute Contract contract) throws Exception {
        ModelAndView modelAndView = new ModelAndView("redirect:/");

        // 키 읽어오기
        KeyPair keyPair = keyManager.readAsymmetricKeyPair(contract.getPublicKeyFile(), contract.getPrivateKeyFile());
        DigitalEnvelope envelope = envelopeManager.createEnvelope(contract.toString(), keyPair.getPublic(), keyPair.getPrivate());
        envelopeManager.saveEnvelopeToFile(envelope, contract.getSignFile() + "_envelope.dat");
        System.out.println("전자봉투 저장 성공: " + contract.getSignFile() + "_envelope.dat");

        return modelAndView;
    }

    @PostMapping("/verify")
    @ResponseBody
    public String verifyDocument(@RequestParam String document, @RequestParam String signature) throws Exception {
        DigitalEnvelope envelope = envelopeManager.loadEnvelopeFromFile("document");
        boolean isValid = envelopeManager.verifySignature(document, envelope.getSignature(), envelope.getPublicKey());
        return isValid ? "ㅇㅋ." : "ㄴㄴ.";
    }
}
