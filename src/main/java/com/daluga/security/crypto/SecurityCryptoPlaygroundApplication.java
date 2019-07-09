package com.daluga.security.crypto;

import com.lambdaworks.crypto.SCryptUtil;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

@SpringBootApplication
public class SecurityCryptoPlaygroundApplication implements CommandLineRunner {

//    Stored in the database, a bcrypt "hash" might look something like this:
//
//      $2a$10$AYX4P5Ykua.JUdnAHp9RUOiVByaGZ6YGh8awMOX2QeFrDgatzgRpa
//      $2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa
//
//    This is actually three fields, delimited by "$":
//
//      - 2a identifies the bcrypt algorithm version that was used.
//      - 10 is the cost factor (strength); 2 to the 10th iterations of the key derivation function
//          are usedv (which is not enough, by the way. I'd recommend a cost of 12 or more.)
//      - vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa is the salt and the
//          cipher text, concatenated and encoded in a modified Base-64. The first 22
//          characters decode to a 16-byte value for the salt. The remaining characters
//          are cipher text to be compared for authentication.

    private static final String SECRET = "mysecretmysecret";
    private static final String SALT = "yoyoma1234";
    private static final String PASSWORD = "12345678";

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityCryptoPlaygroundApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SecurityCryptoPlaygroundApplication.class, args);
    }

    @Override
    public void run(String... strings) throws Exception {
        LOGGER.debug("The SecurityCryptoPlaygroundApplication has started!");

        //LOGGER.debug("===========================================================================");
        //getSecurityProviders();

        LOGGER.debug("===========================================================================");
        LOGGER.debug("AES Encryption");
        executeAESEncryption();

        LOGGER.debug("===========================================================================");
        LOGGER.debug("AES Encryption (With Salt)");
        executeAESEncryptionWithSalt();

        LOGGER.debug("===========================================================================");
        LOGGER.debug("Bcrypt Hash");
        bcryptEncode(PASSWORD);

        LOGGER.debug("===========================================================================");
        LOGGER.debug("Bcrypt Hash (No Spring)");
        bcryptEncodeNative(PASSWORD);

        LOGGER.debug("===========================================================================");
        LOGGER.debug("Scrypt Hash");
        scryptEncode(PASSWORD);

        LOGGER.debug("===========================================================================");
        LOGGER.debug("Scrypt Hash (No Spring) - Prefer this over Bcrypt");
        scryptEncodeNative(PASSWORD);

        LOGGER.debug("===========================================================================");
        LOGGER.debug("Pbkdf2 Hash - Don't Use This One");
        pbkdf2Encode(PASSWORD);

        LOGGER.debug("===========================================================================");
        LOGGER.debug("Argon2 Hash - Is this the best one?");
        argon2Encode(PASSWORD);

        LOGGER.debug("===========================================================================");
        LOGGER.debug("The SecurityCryptoPlaygroundApplication has ended!");
    }

    private void executeAESEncryption() {
        String encryptedValue = AESEncryption.encrypt(PASSWORD, SECRET);
        String decryptedValue = AESEncryption.decrypt(encryptedValue, SECRET);

        LOGGER.debug("AESEncryption Encrypted value: " + encryptedValue);
        LOGGER.debug("AESEncryption Decrypted value: " + decryptedValue);

        if (PASSWORD.matches(decryptedValue)) {
            LOGGER.debug("AESEncryption Encryption/Decryption Matches!!!");
        } else {
            LOGGER.debug("AESEncryption Encryption/Decryption DOES NOT Match!!!");
        }
    }

    private void executeAESEncryptionWithSalt() throws NoSuchAlgorithmException {
        // To make it a bit more secure, add a generated salt. Note that you would need to store this value
        // in say a database if you need to decrypt the value.
        String salt = AESEncryption.getGeneratedSalt();

        String encryptedValue = AESEncryption.encrypt(PASSWORD, SECRET, salt);
        String decryptedValue = AESEncryption.decrypt(encryptedValue, SECRET, salt);

        LOGGER.debug("AESEncryption Encrypted value: " + encryptedValue);
        LOGGER.debug("AESEncryption Decrypted value: " + decryptedValue);

        if (PASSWORD.matches(decryptedValue)) {
            LOGGER.debug("AESEncryption Encryption/Decryption Matches!!!");
        } else {
            LOGGER.debug("AESEncryption Encryption/Decryption DOES NOT Match!!!");
        }
    }

    private void argon2Encode(String password) {
        Argon2 argon2 = Argon2Factory.create();

        int N = 65536;
        int r = 2;
        int p = 1;

        try {
            String hashedPassword = argon2.hash(r, N, p, password.toCharArray());
            LOGGER.debug("Argon2 Hashed Password: " + hashedPassword);

            if (argon2.verify(hashedPassword, PASSWORD)) {
                LOGGER.debug("THEY MATCHED!!!");
            } else {
                LOGGER.debug("Something went wrong!!!");
            }
        } finally {
            argon2.wipeArray(password.toCharArray());
        }

    }

    private void scryptEncodeNative(String password) {
        // See: https://github.com/wg/scrypt
        int N = 16384;   // CPU cost parameter
        int r = 8;       // Memory cost parameter
        int p = 1;       // Parallelization parameter
        String hashedPassword = SCryptUtil.scrypt(password, N, r, p);
        LOGGER.debug("Scrypt Hashed Password: " + hashedPassword);

        if (SCryptUtil.check(password, hashedPassword)) {
            LOGGER.debug("THEY MATCHED!!!");
        } else {
            LOGGER.debug("Something went wrong!!!");
        }
    }

    private void bcryptEncodeNative(String password) {
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
        LOGGER.debug("Bcrypt Hashed Password: " + hashedPassword);

        if (BCrypt.checkpw(password, hashedPassword)) {
            LOGGER.debug("THEY MATCHED!!!");
        } else {
            LOGGER.debug("Something went wrong!!!");
        }
    }

    private void scryptEncode(String password) {

        String hashedPassword = generateScryptPasswordHash(password);

        boolean passwordMatch = isScryptPasswordMatch(password, hashedPassword);
        if (passwordMatch) {
            LOGGER.debug("THEY MATCHED!!!");
        } else {
            LOGGER.debug("Something went wrong!!!");
        }
    }

    private boolean isScryptPasswordMatch(String password, String hashedPassword) {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();

        return encoder.matches(password, hashedPassword);
    }

    private String generateScryptPasswordHash(String password) {
        // The higher the strength the more of a performance price.
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        String hashedPassword = encoder.encode(password);
        LOGGER.debug("Scrypt Hashed Password: " + hashedPassword);
        return hashedPassword;
    }

    private void bcryptEncode(String password) {

        String hashedPassword = generateBcryptPasswordHash(password);

        boolean passwordMatch = isBcryptPasswordMatch(password, hashedPassword);
        if (passwordMatch) {
            LOGGER.debug("THEY MATCHED!!!");
        } else {
            LOGGER.debug("Something went wrong!!!");
        }
    }

    private boolean isBcryptPasswordMatch(String password, String hashedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        return encoder.matches(password, hashedPassword);
    }

    private String generateBcryptPasswordHash(String password) {
        // The higher the strength the more of a performance price.
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String hashedPassword = encoder.encode(password);
        LOGGER.debug("Bcrypt Hashed Password: " + hashedPassword);
        return hashedPassword;
    }

    private void pbkdf2Encode(String password) {

        String hashedPassword = generatePbkdf2PasswordHash(password);

        boolean passwordMatch = isPbkdf2PasswordMatch(password, hashedPassword);
        if (passwordMatch) {
            LOGGER.debug("THEY MATCHED!!!");
        } else {
            LOGGER.debug("Something went wrong!!!");
        }
    }

    private String generatePbkdf2PasswordHash(CharSequence password) {
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();
        String hashedPassword = encoder.encode(password);
        LOGGER.debug("Pbkdf2 Hashed Password: " + hashedPassword);
        return hashedPassword;
    }

    private boolean isPbkdf2PasswordMatch(CharSequence password, String hashedPassword) {
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();

        return encoder.matches(password, hashedPassword);
    }

    private void getSecurityProviders() {
        Provider[] providers = Security.getProviders();

        for(Provider provider : providers){
            LOGGER.debug("===========================================================================");
            LOGGER.debug("Provider Name: " + provider.getName());
            LOGGER.debug("Provider Info: " + provider.getInfo());
            provider.getServices().forEach(service -> {
                //LOGGER.debug("Algorithm: " + service.getAlgorithm());
                //LOGGER.debug("Class Name: " + service.getClassName());
                //LOGGER.debug("Type " + service.getType());
                LOGGER.debug("toString " + service.toString());
            });
        }
    }
}
