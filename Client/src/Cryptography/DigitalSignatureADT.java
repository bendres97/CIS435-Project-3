package Cryptography;

/**
 * ADT for Digital Signatures
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface DigitalSignatureADT
{

    /**
     * Encrypts the supplied message using the supplied modulus and public key.
     *
     * @param msg String representation of the plaintext message to encrypt.
     * @return The encrypted digital signature.
     */
    public Signature sign(String msg);

    /**
     * authenticate the Digital Signature
     *
     * @param signature The Digital Signature to check
     * @return True if the signature is valid
     */
    public boolean authenticate(Signature signature);
}
