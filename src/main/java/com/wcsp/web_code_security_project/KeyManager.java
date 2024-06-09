package com.wcsp.web_code_security_project;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;

public class KeyManager {
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int ASYMMETRIC_KEY_LENGTH = 1024;
    private static final int SYMMETRIC_KEY_LENGTH= 256;

    // 전자서명 - 비대칭키 생성
    public KeyPair createAsymmetricKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(ASYMMETRIC_KEY_LENGTH);
        return keyPairGenerator.generateKeyPair();
    }

    // 비밀키 - 대칭키 생성
    public SecretKey createSymmetricKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGen.init(SYMMETRIC_KEY_LENGTH);
        return keyGen.generateKey();
    }

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
    public void saveSecretKey(String fileName, SecretKey secretKey) {
        try (FileOutputStream fos = new FileOutputStream(fileName);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(secretKey);
        } catch (IOException e) {
            throw new RuntimeException("Secret Key 파일 저장 에러 : " + e.getMessage(), e);
        }
    }


    // 비대칭키 파일 읽기
    public KeyPair readAsymmetricKeyPair(String publicKeyFile, String privateKeyFile) throws IOException, ClassNotFoundException {
        PublicKey publicKey;
        PrivateKey privateKey;

        // 공개키 읽기
        try (FileInputStream fis = new FileInputStream(publicKeyFile);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            publicKey = (PublicKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("public key 파일 읽기 실패 : " + e.getMessage(), e);
        }

        // 사설키 읽기
        try (FileInputStream fis = new FileInputStream(privateKeyFile);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            privateKey = (PrivateKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("private key 파일 읽기 실패 : " + e.getMessage(), e);
        }

        return new KeyPair(publicKey, privateKey);
    }


    // 비밀키 파일 읽기
    public SecretKey readSymmetricKey(String fileName) throws IOException, ClassNotFoundException {
        try (FileInputStream fis = new FileInputStream(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (SecretKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Secret key 파일 읽기 실패 : " + e.getMessage(), e);
        }
    }

    // 공개키 파일 읽기
    public PublicKey readPublicKey(String publicKeyFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(publicKeyFile);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (PublicKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Public key 파일 읽기 실패 : " + e.getMessage(), e);
        }
    }
}
