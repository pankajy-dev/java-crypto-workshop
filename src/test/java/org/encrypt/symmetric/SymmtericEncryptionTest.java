package org.encrypt.symmetric;

import java.util.Base64;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

class SymmtericEncryptionTest {

    @Test
    void performEncryption() throws Exception{
        //2.c. Get the secretKey to be used for encryption
        SecretKey secretKey = SymmtericEncryption.generateAESKey();
        String plainText = "secret for CB success";
        System.out.println("Before encryption : " + plainText);

        // 2.e. Do encryption of the plain text using the secret key.
        String cipherText = SymmtericEncryption.performEncryption(plainText, secretKey);
        System.out.println(cipherText);

        // Extract the initialization vector(IV) used for encryption, same will be used for decryption.
        String[] parts = cipherText.split(":");

        // Extract IV and the encrypted text
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        //2.e.v Retrieve the original text using secret key and encrypted text.
        String decryptedPlainText = SymmtericEncryption.performDecryption(cipherText, secretKey);
        System.out.println(decryptedPlainText);
    }
}