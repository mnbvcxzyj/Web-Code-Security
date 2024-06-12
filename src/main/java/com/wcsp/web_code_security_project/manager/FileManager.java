package com.wcsp.web_code_security_project.manager;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;

public class FileManager {
    // 비대칭키 파일 저장
    public void saveAsymmetricKeyPair(String publicFile, String privateFile, KeyPair keyPair) {
        // 공개키 저장
        try (FileOutputStream fos = new FileOutputStream(publicFile);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(keyPair.getPublic());
        } catch (IOException e) {
            throw new RuntimeException("public key 파일 저장 에러 : " + e.getMessage(), e);
        }

        // 사설키 저장
        try (FileOutputStream fos = new FileOutputStream(privateFile);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(keyPair.getPrivate());
        } catch (IOException e) {
            throw new RuntimeException("private key 파일 저장 에러 : " + e.getMessage(), e);
        }
    }

    // 비밀키 파일 저장
    public void saveSecretKey(String fileName, SecretKey secretKey) throws IOException {
        saveFile(secretKey.getEncoded(), fileName);
    }

    // 키 파일 읽기
    public Key readKeyFile(String keyFile) {
        try (FileInputStream fis = new FileInputStream(keyFile);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (Key) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Public key 파일 읽기 실패 : " + e.getMessage(), e);
        }
    }

    // 파일 저장
    public void saveFile(byte[] data, String fileName) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(data);
        }
    }

    // 파일 읽기
    public byte[] readFile(String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName)) {
            return fis.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException("파일 읽기 실패: " + e.getMessage(), e);
        }
    }
}
