package com.daluga.security.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

import java.security.NoSuchAlgorithmException;

@SpringBootApplication
public class SecurityCryptoPlaygroundApplication implements CommandLineRunner {

//    Stored in the database, a bcrypt "hash" might look something like this:
//
//      $2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa
//
//    This is actually three fields, delimited by "$":
//
//      - 2a identifies the bcrypt algorithm version that was used.
//      - 10 is the cost factor; 2 to the 10th iterations of the key derivation function
//          are usedv(which is not enough, by the way. I'd recommend a cost of 12 or more.)
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

        //CharSequence password = "12345678";

        LOGGER.debug("===========================================================================");
        LOGGER.debug("AES Encryption");
        executeAESEncryption();

        LOGGER.debug("===========================================================================");
        LOGGER.debug("AES Encryption (With Salt)");
//        executeAESEncryptionWithSalt();

//        bcryptEncode(password);
//        pbkdf2Encode(password);

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

    private void pbkdf2Encode(CharSequence password) {

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
        LOGGER.debug("Pass -> " + hashedPassword);
        return hashedPassword;
    }

    private boolean isPbkdf2PasswordMatch(CharSequence password, String hashedPassword) {
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();

        return encoder.matches(password, hashedPassword);
    }

    private void bcryptEncode(CharSequence password) {

        String hashedPassword = generateBcryptPasswordHash(password);

        boolean passwordMatch = isBcryptPasswordMatch(password, hashedPassword);
        if (passwordMatch) {
            LOGGER.debug("THEY MATCHED!!!");
        } else {
            LOGGER.debug("Something went wrong!!!");
        }
    }

    private boolean isBcryptPasswordMatch(CharSequence password, String hashedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        return encoder.matches(password, hashedPassword);
    }

    private String generateBcryptPasswordHash(CharSequence password) {
        String salt = BCrypt.gensalt(10);
        LOGGER.debug("Salt -> " + salt);
        // The higher the strength the more of a performance price.
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);
        String hashedPassword = encoder.encode(password);
        LOGGER.debug("Pass -> " + hashedPassword);
        return hashedPassword;
    }
}
