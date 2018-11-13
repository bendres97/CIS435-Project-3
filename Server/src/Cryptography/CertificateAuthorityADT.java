package Cryptography;
import Network.Receiver;

/**
 * ADT for Certificate Authority
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public interface CertificateAuthorityADT
{

    /**
     * Returns the certificate for the specified receiver
     *
     * @param sender The sender to get a certificate for
     * @return The certificate.
     */
    public Certificate getCertificate(Receiver receiver);

    /**
     * Registers a receiver with the CA.
     *
     * @param user The User to register
     */
    public void register(Receiver receiver);
}
