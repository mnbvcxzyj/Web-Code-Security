package com.wcsp.web_code_security_project.controller;

import com.wcsp.web_code_security_project.DigitalEnvelopeManager;
import com.wcsp.web_code_security_project.KeyManager;
import com.wcsp.web_code_security_project.domain.Contract;
import com.wcsp.web_code_security_project.domain.DigitalEnvelope;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;

@Controller
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
    public String generateKeys(@RequestParam String keyName) throws Exception {
        KeyPair keyPair = keyManager.createAsymmetricKeyPair();
        keyManager.saveAsymmetricKeyPair(keyName + "_public.key", keyName + "_private.key", keyPair);

        return keyName + "_public.key, " + keyName + "_private.key로 키 저장 완료!";
    }

    // 계약서 작성 및 전자 서명
    @PostMapping("/sign")
    public String signDocument(@ModelAttribute Contract contract, Model model) throws Exception {
        // 원본 파일 저장
        envelopeManager.saveOriginFile(contract.toString(), contract.getOriginFile());

        // 전자 서명
        KeyPair keyPair = keyManager.readAsymmetricKeyPair(contract.getPublicKeyFile(), contract.getPrivateKeyFile());
        DigitalEnvelope envelope = envelopeManager.createEnvelope(contract.toString(), keyPair.getPublic(), keyPair.getPrivate());
        envelopeManager.saveEnvelopeToFile(envelope, contract.getSignFile() + "_envelope.dat");
        System.out.println("전자봉투 저장 성공: " + contract.getSignFile() + "_envelope.dat");

        model.addAttribute("contract", contract.toString());

        return "contractDetail";
    }

    // 전자 서명 검증
    @PostMapping("/verify")
    @ResponseBody
    public String verifyDocument(@RequestParam String originFile, @RequestParam String publicKeyFile, @RequestParam String signFile) throws Exception {
        String data = envelopeManager.readOriginFile(originFile);
        DigitalEnvelope envelope = envelopeManager.loadEnvelopeFromFile(signFile);
        PublicKey publicKey = keyManager.readPublicKey(publicKeyFile);

        boolean isValid = envelopeManager.verifySignature(data, envelope.getSignature(), publicKey);

        return isValid ? "문서가 일치합니다." : "문서가 일치하지 않습니다.";
    }
}
