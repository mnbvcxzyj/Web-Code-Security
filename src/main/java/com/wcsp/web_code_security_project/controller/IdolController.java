package com.wcsp.web_code_security_project.controller;

import com.wcsp.web_code_security_project.service.DigitalEnvelopeService;
import com.wcsp.web_code_security_project.manager.FileManager;
import com.wcsp.web_code_security_project.manager.KeyManager;
import com.wcsp.web_code_security_project.domain.Contract;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Controller
public class IdolController {
    private final KeyManager keyManager = new KeyManager();
    private final FileManager fileManager = new FileManager();
    private final DigitalEnvelopeService envelopeService = new DigitalEnvelopeService();


    public IdolController() {
    }

    // 키 생성
    @PostMapping("/keys")
    @ResponseBody
    public String generateKeys(@RequestParam String keyName) throws Exception {
        KeyPair keyPair = keyManager.createAsymmetricKeyPair();
        fileManager.saveAsymmetricKeyPair(keyName + "_public.key", keyName + "_private.key", keyPair);

        return keyName + "_public.key, " + keyName + "_private.key로 키 저장 완료! 🔐";
    }

    @PostMapping("/sign")
    public String signDocument(@ModelAttribute Contract contract, Model model) throws Exception {
        // 비밀키 저장
        SecretKey secretKey = keyManager.createSymmetricKey();
        fileManager.saveSecretKey("secret.key", secretKey);

        // 공개키 (사장님), 비밀키 (연습생)
        PublicKey publicKey = (PublicKey) fileManager.readKeyFile(contract.getPublicKeyFile());
        PrivateKey privateKey = (PrivateKey) fileManager.readKeyFile(contract.getPrivateKeyFile());

        // 파일명 형식
        String signFile = contract.getSignFile() + "_sign.dat";
        String contractFile = contract.getSignFile() + "_contract.dat";
        String envelopeFile = contract.getSignFile() + "_envelope.dat";

        // 서명 생성 (서명, 계약서 암호화)
        envelopeService.createDigitalSign(contract.toString(), privateKey, secretKey, signFile, contractFile);

        // 봉투 생성 (공개키 -> 비밀키 암호화)
        envelopeService.createDigitalEnvelope(publicKey, secretKey, envelopeFile);

        model.addAttribute("contract", contract.toString());

        return "contractDetail";
    }

    // 검증
    @PostMapping("/verify")
    @ResponseBody
    public String verifyDocument(@RequestParam String envFile, @RequestParam String signFile, @RequestParam String contractFile, @RequestParam String privateKeyFile, @RequestParam String publicKeyFile) throws Exception {
        PrivateKey bossPrivateKey = (PrivateKey) fileManager.readKeyFile(privateKeyFile);
        PublicKey trainPublicKey = (PublicKey) fileManager.readKeyFile(publicKeyFile);

        boolean isValid = envelopeService.verifyEnvelope(envFile, signFile, contractFile, bossPrivateKey, trainPublicKey);
        return isValid ? "문서가 일치합니다." : "문서가 일치하지 않습니다.";
    }
}