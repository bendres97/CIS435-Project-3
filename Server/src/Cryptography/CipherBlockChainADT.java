package Cryptography;


/**
 * ADT for Cipher Block Chain
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface CipherBlockChainADT
{

    /**
     * Encrypts the given input string starting at the given Initialization
     * Vector
     *
     * @param input The string to encrypt
     * @param IV The Initialization Vector in Binary
     * @return The encrypted String
     */
    public String Encrypt(String input, String IV);

    /**
     * Decrypts the given String.
     *
     * @param input The string to decrypt
     * @param IV The Initialization Vector in Binary
     * @return The decrypted String
     */
    public String Decrypt(String input, String IV);
}
