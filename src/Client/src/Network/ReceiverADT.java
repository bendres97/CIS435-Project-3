package Network;

import Cryptography.Certificate;
import Cryptography.RSAKey;
import java.math.BigInteger;

/**
 *
 * This class defines the interface for the Receiver Class that describes what
 * the receiver is receiving on his/her end.
 *
 * @author Andrew Bradley
 * @author Bryan Endres
 * @since 10-29-2018
 */
public interface ReceiverADT
{

    /**
     * <p>
     * Gets the packet from the network that was sent by the sender.
     *
     * @param net This would be pulled from the constructor in the Network
     * Prints out receiving packets Trying to receive the packets from sender
     * @return The received packet
     */
    public Packet receive(Network net);

    /**
     * <p>
     * Returns the generated certificate that was distributed by the CA.
     *
     * @return the certificate
     */
    public Certificate getCertificate();

    /**
     * <p>
     * Returns the public RSA key of this Receiver
     *
     * @return the public RSA key
     */
    public RSAKey getPublicKey();

    /**
     * <p>
     * Decrypts the supplied message using the Receiver's private key.
     *
     * @param message The message to decrypt
     * @return The decrypted message
     */
    public BigInteger decryptMessage(BigInteger message);
}
