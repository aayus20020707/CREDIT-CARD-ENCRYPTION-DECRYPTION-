import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CreditCardEncryption {

    private static final String KEY = "YourSecretKey123"; // Replace with your own secret key

    /**
     * Encrypts the given credit card number using the AES algorithm.
     *
     * @param creditCardNumber The credit card number to be encrypted.
     * @return The encrypted credit card number as a Base64-encoded string.
     */
    public static String encrypt(String creditCardNumber) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(creditCardNumber.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts the given encrypted credit card number using the AES algorithm.
     *
     * @param encryptedCreditCard The encrypted credit card number as a Base64-encoded string.
     * @return The decrypted credit card number.
     */
    public static String decrypt(String encryptedCreditCard) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = Base64.getDecoder().decode(encryptedCreditCard);
            byte[] originalBytes = cipher.doFinal(decryptedBytes);
            return new String(originalBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String creditCardNumber = "1234-5678-9012-3456"; // Replace with the credit card number you want to encrypt

        // Encryption
        String encryptedCreditCard = encrypt(creditCardNumber);
        System.out.println("Encrypted Credit Card: " + encryptedCreditCard);

        // Decryption
        String decryptedCreditCard = decrypt(encryptedCreditCard);
        System.out.println("Decrypted Credit Card: " + decryptedCreditCard);
    }
}