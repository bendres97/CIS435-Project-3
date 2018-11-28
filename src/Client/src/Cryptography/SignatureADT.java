package Cryptography;

import java.math.BigInteger;

/**
 * The ADT for a Signature
 *
 * @author bendr
 * @date 9-30-2018
 */
interface SignatureADT
{

    /**
     * Returns the encrypted hash of the message.
     *
     * @return The encrypted hash
     */
    public BigInteger getEncryptedHash();

    /**
     * Returns the original message
     *
     * @return The original message
     */
    public BigInteger getMessage();

    /**
     * Returns the public key
     *
     * @return The public key
     */
    public RSAKey getPublicKey();
}
