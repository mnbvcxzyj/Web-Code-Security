package com.wcsp.web_code_security_project;

import com.wcsp.web_code_security_project.domain.Contract;
import com.wcsp.web_code_security_project.domain.DigitalEnvelope;

import java.io.*;
import java.security.*;
import java.util.Arrays;

public class DigitalEnvelopeManager {
    private static final String SIGN_ALGORITHM = "SHA256withRSA";


    // 원본 파일 저장
    public void saveOriginFile(String contract, String fileName){
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            writer.write(contract);
        } catch (IOException e) {
            throw new RuntimeException("원본 파일 저장 에러 : " + e.getMessage(), e);
        }
    }

    // 원본 파일 읽어 오기
    // 원본 파일 읽어오기
    public String readOriginFile(String fileName) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            throw new RuntimeException("데이터 파일 읽기 실패: " + e.getMessage(), e);
        }
        return sb.toString().trim();
    }

    // 전자봉투 생성
    // - 전자서명 생성 -> 원문 +  publickey를 private키로 암호화 -> 영희의 public key로 암호화
    // ? : 0) 해시값을 사설키로 암호화
    // ? : 1) (전자서명, 원문, 자신의 공개키)를 자기 비밀키로 암호화 / 2) 전자봉투 = 영희 공개키로 시크릿키를 암호화
    // ? : 1) 비밀키로 암호화한 결과 + 2) 비밀키가 암호화된 전자봉투를 보냄
    public DigitalEnvelope createEnvelope(String data, PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException, NoSuchAlgorithmException {

        // #4) 보안에 민감한 메소드들이 검증된 매개변수를 가지고 호출되도록 보장하라
        if (data == null || data.isEmpty() || publicKey == null || privateKey == null) {
            throw new IllegalArgumentException("검증 되지 않은 매개변수 입니다.");
        }

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
    public boolean verifySignature(String data, byte[] signature, PublicKey publicKey) throws GeneralSecurityException {
        // 객체 생성
        Signature sig = Signature.getInstance(SIGN_ALGORITHM);

        // 개인키나 공개키로 서명자 초기화
        sig.initVerify(publicKey);

        // 검증 데이터
        sig.update(data.getBytes());

        // 서명 검증
        return sig.verify(signature);
    }
}
