package com.wcsp.web_code_security_project.service;

import com.wcsp.web_code_security_project.manager.FileManager;
import com.wcsp.web_code_security_project.manager.KeyManager;

import javax.crypto.SecretKey;
import java.security.*;

public class DigitalEnvelopeService {
    private final KeyManager keyManager = new KeyManager();
    private final FileManager fileManager = new FileManager();
    private static final String SIGN_ALGORITHM = "SHA256withRSA";

    // 전자 서명 생성 및 파일 저장
    public void createDigitalSign(String data, PrivateKey privateKey, SecretKey secretKey, String signFile, String contractFile) throws Exception {
        if (data == null || data.isEmpty() || privateKey == null || secretKey == null) {
            throw new IllegalArgumentException("검증되지 않은 매개변수입니다.");
        }

        // 1. 원본 데이터로 서명 생성
        Signature sig = Signature.getInstance(SIGN_ALGORITHM);
        sig.initSign(privateKey);
        sig.update(data.getBytes());
        byte[] signature = sig.sign();

        // 2. 서명을 비밀키로 암호화
        byte[] encryptedSignature = keyManager.encryptData(signature, secretKey);

        // 3. 계약서 비밀키로 암호화
        byte[] encryptedContract = keyManager.encryptData(data.getBytes(), secretKey);

        // 4. 암호화 된 서명과 계약서를 파일로 저장
        fileManager.saveFile(encryptedSignature, signFile);
        fileManager.saveFile(encryptedContract, contractFile);
    }

    // 전자 봉투 생성
    public void createDigitalEnvelope(PublicKey publicKey, SecretKey secretKey, String envelopeFile) throws Exception {
        // 1. Secret key를 사장님의 public key로 암호화 해서 저장
        byte[] encryptedSecretKey = keyManager.encryptSecretKey(secretKey, publicKey);

        // 2. 암호화된 Secret Key를 파일로 저장
        fileManager.saveFile(encryptedSecretKey, envelopeFile);
    }

    public boolean verifyEnvelope(String envelopeFile, String signFile, String contractFile, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // 0. 사장님의 Private key로 전자봉투 복호화하여 Secret.key 획득
        byte[] encryptedSecretKey = fileManager.readFile(envelopeFile);
        SecretKey secretKey = keyManager.decryptSecretKey(encryptedSecretKey, privateKey);

        // 1. 서명을 Secret key로 복호화
        byte[] encryptedSignature = fileManager.readFile(signFile);
        byte[] decryptedSignature = keyManager.decryptData(encryptedSignature, secretKey);

        // 2. 계약서 복호화
        byte[] encryptedContract = fileManager.readFile(contractFile);
        byte[] decryptedContract = keyManager.decryptData(encryptedContract, secretKey);

        // 3. 원본 데이터로 서명 검증
        Signature sig = Signature.getInstance(SIGN_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(decryptedContract);

        // 4. 복호화 된 서명을 사용 하여 서명 검증
        boolean isVerified = sig.verify(decryptedSignature);
        System.out.println("검증) 결과: " + isVerified);
        return isVerified;
    }
}
