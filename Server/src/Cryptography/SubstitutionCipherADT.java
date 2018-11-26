package Cryptography;


/**
 * The ADT for a Substitution Cipher
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface SubstitutionCipherADT
{

    /**
     * Encrypts the supplied input using the supplied substitution key.
     *
     * @param input The plaintext message to encrypt
     * @param substitutionKey The substitution key to use
     * @return The encrypted ciphertext
     */
    public String Encrypt(String input, char[] substitutionKey);

    /**
     * Decrypts the supplied ciphertext using the supplied substitution key.
     *
     * @param cryptInput The ciphertext to decrypt
     * @param substitutionKey The substitution key used for encryption
     * @return The decrypted plaintext
     */
    public String Decrypt(String cryptInput, char[] substitutionKey);
}
