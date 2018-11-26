package Cryptography;


import java.math.BigInteger;

/**
 * ADT for Message Authentication Code
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface MACADT
{

    /**
     * Encrypts the supplied message with the supplied secret
     *
     * @param msg BigInteger representation of the message to encrypt
     * @param secret BigInteger representation of the secret
     * @return The encrypted message
     */
    public BigInteger authenticate(BigInteger message, BigInteger secret);

    /**
     * Decrypt the given cipher with the given initial secret and hashed secret.
     *
     * @param msg The cipher to decrypt
     * @param secret The hashed secret
     * @return The plaintext message.
     */
    public boolean checkIntegrity(BigInteger message, BigInteger secret);
}
