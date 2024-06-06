package com.wcsp.web_code_security_project;

import com.wcsp.web_code_security_project.domain.DigitalEnvelope;

import java.io.*;
import java.security.*;
import java.util.Arrays;

public class DigitalEnvelopeManager {
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String HASH_ALGORITHM = "MD5";

    // 해시값 생성
    public byte[] createHash(String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        md.update(data.getBytes());
        byte[] hashData = md.digest();

        return hashData;
    }


    // 전자봉투 생성
    // - 전자서명 생성 -> 원문 +  publickey를 private키로 암호화 -> 영희의 public key로 암호화
    // ? : 0) 해시값을 사설키로 암호화
    // ? : 1) (전자서명, 원문, 자신의 공개키)를 자기 비밀키로 암호화 / 2) 전자봉투 = 영희 공개키로 시크릿키를 암호화
    // ? : 1) 비밀키로 암호화한 결과 + 2) 비밀키가 암호화된 전자봉투를 보냄
    public DigitalEnvelope createEnvelope(String data, PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException, NoSuchAlgorithmException {
        // 객체 생성
        Signature sig = Signature.getInstance(SIGN_ALGORITHM);

        // 서명자 초기화
        sig.initSign(privateKey);

        // 원문의 해시값 데이터 저장
        sig.update(data.getBytes());

        // 전자 서명 생성
        byte[] signature = sig.sign();
        return new DigitalEnvelope(data, signature, publicKey);
    }

    // 전자봉투 저장
    public void saveEnvelopeToFile(DigitalEnvelope envelope, String fileName) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(envelope);
        } catch (IOException e) {
            throw new RuntimeException("전자 봉투 파일 저장 에러 : " + e.getMessage(), e);
        }
    }

    // 전자봉투 로드
    public DigitalEnvelope loadEnvelopeFromFile(String fileName) throws IOException, GeneralSecurityException, ClassNotFoundException {
        try (FileInputStream fis = new FileInputStream(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (DigitalEnvelope) ois.readObject();
        }
    }

    // 전자 서명 검증
    // 철수 공개키로 해시값을 복호화해서 원본 값ㅎ이랑 비교
    // 영희의 사설키로 복호화해서 철수의 공개키 가져오기
    // 비밀키로 전자서명과 평문, 인증서(?) 복호화
    // 공개키를 가져와서 복호화 하고 원문과 비교
    public boolean verifySignature(String document, byte[] signature, PublicKey publicKey) throws GeneralSecurityException {
        // 객체 생성
        Signature sig = Signature.getInstance(SIGN_ALGORITHM);

        // 개인키나 공개키로 서명자 초기화
        sig.initVerify(publicKey);

        // 검증 데이터
        sig.update(document.getBytes());

        // 서명 검증
        return sig.verify(signature);
    }
}
