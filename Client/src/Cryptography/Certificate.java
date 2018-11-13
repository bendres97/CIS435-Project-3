package Cryptography;


import java.math.BigInteger;

/**
 * Holds the RSAKeys for both the CA and the encrypted RSAKey for the user
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class Certificate implements CertificateADT
{

    private final RSAKey CA_KEY;
    private final RSAKey USER_KEY;

    public Certificate(RSAKey userKey, RSAKey keyCA)
    {
        CA_KEY = keyCA;
        USER_KEY = userKey;
    }

    @Override
    public RSAKey getCAKey()
    {
        return CA_KEY;
    }

    @Override
    public RSAKey getUserKey()
    {
        return USER_KEY;
    }

    /**
     * Static method to decrypt a CA certificate.
     *
     * @param certificate The certificate to decrypt
     * @return The decrypted RSAKey from the certificate
     */
    public static RSAKey decryptCertificate(Certificate certificate)
    {
        //Get CA and User RSAKeys and user N and EXP values
        RSAKey caKey = certificate.getCAKey();
        RSAKey userKey = certificate.getUserKey();
        BigInteger cipherN = userKey.getN();
        BigInteger cipherE = userKey.getEXP();

        //Decrype the user key attributes 
        BigInteger n = cipherN.modPow(caKey.getEXP(), caKey.getN());
        BigInteger e = cipherE.modPow(caKey.getEXP(), caKey.getN());

        //Create and return a new RSAKey containing the decrypted User RSAKey
        return new RSAKey(n, e);
    }
}
