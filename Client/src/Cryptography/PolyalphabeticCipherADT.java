package Cryptography;


/**
 *The ADT for Polyalphabetic Cipher.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface PolyalphabeticCipherADT
{

    /**
     * Encrypts the given message using the given shifter.
     *
     * @param msg The message to encrypt
     * @param shift The shift to use
     * @return the encrypted ciphertext.
     */
    public String Encrypt(String msg, String shift);

    /**
     * Decrypts the given ciphertext using the given shifter.
     *
     * @param msg The ciphertext to decrypt
     * @param shift The shift used for encryption
     * @return The decrypted plaintext
     */
    public String Decrypt(String msg, String shift);
}
