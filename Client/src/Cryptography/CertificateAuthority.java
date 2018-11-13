package Cryptography;


import Network.Receiver;
import java.math.BigInteger;
import java.util.HashMap;
/**
 * Holds the RSA object for CA and the mapping of users and their certificates
 * @author Bryan Endres ID: 8
 * @date 9-30-2018

 */
public class CertificateAuthority implements CertificateAuthorityADT
{
    //Bit Length is specified so that the RSA will still work with large key values. BIT_LENGTH should be twice that of what is currently being used in RSA.
    private final static int BIT_LENGTH = 1024;
    private final HashMap<Receiver, Certificate> CERTIFICATES;
    private static final RSA RSA_OBJ = new RSA(BIT_LENGTH); //overloaded constructor in RSA takes BIT_LENGTH as an argument 

    /**
     * Constructor instantiates a new HashMap to hold certificates in.
     */
    public CertificateAuthority()
    {
        CERTIFICATES = new HashMap();
    }

    @Override
    public Certificate getCertificate(Receiver receiver)
    {
        return CERTIFICATES.get(receiver);
    }

    @Override
    public void register(Receiver receiver)
    {
        //Specify CA and user keys
        RSAKey privateKey = RSA_OBJ.getPrivateKey();
        RSAKey userKey = receiver.getPublicKey();
        
        //Encrypt User's public key with CA's private key
        BigInteger n = userKey.getN().modPow(privateKey.getEXP(), privateKey.getN());
        BigInteger e = userKey.getEXP().modPow(privateKey.getEXP(), privateKey.getN());
        
        //Create a certificate binding these keys and place it in the HashMap
        Certificate certificate = new Certificate(new RSAKey(n, e), RSA_OBJ.getPublicKey());
        CERTIFICATES.put(receiver, certificate);
    }
    
    public RSAKey getPublicKey()
    {
        return RSA_OBJ.getPublicKey();
    }
}
