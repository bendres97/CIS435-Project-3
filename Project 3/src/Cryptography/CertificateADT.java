package Cryptography;


/**
 *ADT for Certificate Object
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
interface CertificateADT
{

    /**
     * Returns the RSAKey for the Certificate Authority
     *
     * @return CA's RSAKey
     */
    public RSAKey getCAKey();

    /**
     * Returns the RSAKey for the User
     *
     * @return User's RSAKey
     */
    public RSAKey getUserKey();
}
