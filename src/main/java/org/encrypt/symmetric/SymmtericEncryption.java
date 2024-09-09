package org.encrypt.symmetric;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmtericEncryption {

    private static final String AES = "AES";
    private static final String AES_CBC_ALGO = "AES/CBC/PKCS5Padding";

    public static SecretKey generateAESKey() throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static byte[] createInitializationVector(int blockSize){
        byte[] iv = new byte[blockSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String performEncryption(String plainText, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CBC_ALGO);

        byte[] iv = createInitializationVector(cipher.getBlockSize());
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        String cipherText = Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
        return cipherText;
    }

    public static String performDecryption(String cipherText, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CBC_ALGO);
        String[] parts = cipherText.split(":");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }
}
