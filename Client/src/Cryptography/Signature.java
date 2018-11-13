package Cryptography;


import java.math.BigInteger;

/**
 * Signature holds the Encrypted Hash, message, and public key for a user's
 * signature.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class Signature implements SignatureADT
{

    private final BigInteger ENCRYPTED_HASH;
    private final BigInteger MESSAGE;
    private final RSAKey PUBLIC_KEY;

    public Signature(BigInteger encryptedHash, BigInteger message, RSAKey publicKey)
    {
        ENCRYPTED_HASH = encryptedHash;
        MESSAGE = message;
        PUBLIC_KEY = publicKey;
    }

    @Override
    public BigInteger getEncryptedHash()
    {
        return ENCRYPTED_HASH;
    }

    @Override
    public BigInteger getMessage()
    {
        return MESSAGE;
    }

    @Override
    public RSAKey getPublicKey()
    {
        return PUBLIC_KEY;
    }
}
