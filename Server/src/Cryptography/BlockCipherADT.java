package Cryptography;


/**
 *ADT for Block Cipher
 *
 * @author Bryan Endres ID: 8
 */
public interface BlockCipherADT
{

    /**
     * Encrypts the supplied plaintext using the given cipherKey.
     *
     * @param input The plaintext to encrypt
     * @return The encrypted ciphertext
     */
    public String Encrypt(String input);

    /**
     * Decrypts the supplied ciphertext using the given cipherKey.
     *
     * @param output The ciphertext to decrypt
     * @return The decrypted plaintext
     */
    public String Decrypt(String output);
}
