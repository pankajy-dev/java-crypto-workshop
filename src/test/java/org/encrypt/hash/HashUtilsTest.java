package org.encrypt.hash;

import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilsTest {

    @Test
    void createSha2Hash() throws Exception {
        String password = "This-is-my-weak-password-stored-safely";

        byte[] passwordHash = HashUtils.createSha2Hash(password);
        String passwordHashString = Base64.getEncoder().encodeToString(passwordHash);

        System.out.println("Password hash: " + passwordHashString);

        byte[] passwordHashLogin = HashUtils.createSha2Hash(password);
        String passwordHashLoginString = Base64.getEncoder().encodeToString(passwordHashLogin);

        System.out.println("Password hash login: " + passwordHashLoginString);

        assertEquals(passwordHashLoginString, passwordHashString, "Verified user, allow login");
    }
}