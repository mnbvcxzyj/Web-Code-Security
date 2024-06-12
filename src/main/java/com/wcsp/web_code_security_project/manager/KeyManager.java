package com.wcsp.web_code_security_project.manager;

import javax.crypto.*;
import java.security.*;
import java.util.Arrays;

public class KeyManager {
    // 비대칭 = 공개키, 사설키
    private static final String ASYMMETRIC_ALGORITHM = "RSA";

    // 대칭키 - 비밀키
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int ASYMMETRIC_KEY_LENGTH = 2048;
    private static final int SYMMETRIC_KEY_LENGTH = 256;


    // 전자서명 - 비대칭키 생성
    public KeyPair createAsymmetricKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(ASYMMETRIC_KEY_LENGTH);
        return keyPairGenerator.generateKeyPair();
    }

    // 비밀키 - 대칭키 생성
    public SecretKey createSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGen.init(SYMMETRIC_KEY_LENGTH);
        return keyGen.generateKey();
    }


    // 데이터 암호화
    public byte[] encryptData(byte[] data, Key key) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    
    // 데이터 복호화
    public byte[] decryptData(byte[] data, Key key) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(data);
        clearArray(data); // 암호화된 데이터 지우기
        return decryptedData;
    }

    // 배열 비우기
    private void clearArray(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }


    // 비밀키를 공개키로 암호화
    public byte[] encryptSecretKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(secretKey);
    }

    // 개인키로 비밀키 복호화
    public SecretKey decryptSecretKey(byte[] encryptedSecretKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(encryptedSecretKey, SYMMETRIC_ALGORITHM, Cipher.SECRET_KEY);
    }

    // Cipher 초기화
    private Cipher getCipher(int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher;
        if (key instanceof SecretKey) {
            cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        } else if (key instanceof PrivateKey || key instanceof PublicKey) {
            cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }
        cipher.init(mode, key);
        return cipher;
    }
}


