package Cryptography;

import java.math.BigInteger;

/**
 * Digital Signature holds a hash value, RSA object, and an ASCII converter for
 * use with signing and authenticating messages.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class DigitalSignature implements DigitalSignatureADT
{

    private final BigInteger HASH_VALUE;
    private final RSA RSA;
    private final AsciiConverter ASCII;

    /**
     * Default constructor. Hard codes the hash to 1024.
     */
    public DigitalSignature()
    {
        HASH_VALUE = new BigInteger("1024");
        RSA = new RSA();
        ASCII = new AsciiConverter();
    }

    @Override
    public Signature sign(String msg)
    {
        //Convert message to BigInteger and generate a hash.
        BigInteger message = ASCII.StringtoBigInt(msg);
        BigInteger plainHash = message.mod(HASH_VALUE);

        //Get the RSA keys from the RSA object.
        RSAKey publicKey = RSA.getPublicKey();
        RSAKey privateKey = RSA.getPrivateKey();

        //Encrypt the hash
        BigInteger encryptedHash = plainHash.modPow(privateKey.getEXP(), privateKey.getN());

        //Create and a return a new signature containing the hash, message, and public key for decrypting hash.
        return new Signature(encryptedHash, message, publicKey);
    }

    @Override
    public boolean authenticate(Signature signature)
    {
        //Get the public key and decrypt the hash from the signature
        RSAKey publicKey = signature.getPublicKey();
        BigInteger decryptedHash = signature.getEncryptedHash().modPow(publicKey.getEXP(), publicKey.getN());

        //Get the message fromt eh signature and hash it
        BigInteger message = signature.getMessage();
        BigInteger messageHash = message.mod(HASH_VALUE);

        //Check to see if the hashed message and decrypted hash are equal
        return decryptedHash.equals(messageHash);
    }

    public boolean authenticate(BigInteger hash, BigInteger message)
    {
        RSAKey publicKey = RSA.getPublicKey();
        BigInteger decryptedHash = hash.modPow(publicKey.getEXP(), publicKey.getN());

        //Convert message to BigInteger and hash
        BigInteger messageHash = message.mod(HASH_VALUE);

        //Check to see if the hashed message and decrypted hash are equal
        return messageHash.equals(messageHash);
    }
}
