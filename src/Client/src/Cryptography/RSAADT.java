package Cryptography;

import java.math.BigInteger;

/**
 * ADT for an RSA object
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface RSAADT
{

    /**
     * Encrypt the supplied message. Code adapted from
     * https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
     *
     * @param msg The message to encrypt
     * @return The encrypted ciphertext
     */
    public BigInteger Encrypt(BigInteger msg);

    /**
     * Decrypt the supplied ciphertext. Code adapted from
     * https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
     *
     * @param cipherIn The ciphertext to decrypt
     * @return The plaintext message.
     */
    public BigInteger Decrypt(BigInteger cipherIn);

    /**
     * Returns the public key pair.
     *
     * @return the public key pair.
     */
    public RSAKey getPublicKey();

    /**
     * Returns the private key pair.
     *
     * @return The private key pair
     */
    public RSAKey getPrivateKey();

}
