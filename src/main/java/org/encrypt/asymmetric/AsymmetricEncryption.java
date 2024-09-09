package org.encrypt.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;

public class AsymmetricEncryption {

    public static final String RSA = "RSA";

    public static KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        SecureRandom secureRandom = new SecureRandom();

        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.genKeyPair();
    }

    public static byte[] performRsaEncryption(String plainText, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return  cipher.doFinal(plainText.getBytes());
    }

    public static String performDecryption(byte[] cipherText, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText));
    }
}
