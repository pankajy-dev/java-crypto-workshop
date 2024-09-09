package org.encrypt.signature;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Base64;

import org.encrypt.asymmetric.AsymmetricEncryption;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignatureUtilsTest {

    @Test
    public void testSignatureUtils() throws Exception{
        URL url = this.getClass().getClassLoader().getResource("big-file.txt");
        assert url != null;
        Path path = Paths.get(url.toURI());
        byte[] input = Files.readAllBytes(path);

        KeyPair keyPair = AsymmetricEncryption.generateKeyPair();

        byte[] signature = SignatureUtils.createDigitalSignature(input, keyPair.getPrivate());
        System.out.println(Base64.getEncoder().encodeToString(signature));

        boolean isVerified = SignatureUtils.verifySignature(input, signature, keyPair.getPublic());
        assertTrue(isVerified);

        url = this.getClass().getClassLoader().getResource("big-file-new.txt");
        assert url != null;
        path = Paths.get(url.toURI());
        byte[] inputNew = Files.readAllBytes(path);

        isVerified = SignatureUtils.verifySignature(inputNew, signature, keyPair.getPublic());

        assertFalse(isVerified);
    }

}