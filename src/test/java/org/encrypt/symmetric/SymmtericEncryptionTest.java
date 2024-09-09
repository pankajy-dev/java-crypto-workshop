package org.encrypt.symmetric;

import java.util.Base64;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

class SymmtericEncryptionTest {

    @Test
    void performEncryption() throws Exception{
        SecretKey secretKey = SymmtericEncryption.generateAESKey();
        String plainText = "secret for CB success";
        System.out.println("Before encryption : " + plainText);
        String cipherText = SymmtericEncryption.performEncryption(plainText, secretKey);
        System.out.println(cipherText);

        String[] parts = cipherText.split(":");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        String decryptedPlainText = SymmtericEncryption.performDecryption(cipherText, secretKey);
        System.out.println(decryptedPlainText);
    }
}