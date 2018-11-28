package Network;

import java.math.BigInteger;

/**
 * This class defines the interface for the Packet class.
 *
 * @author Andrew Bradley
 * @author Bryan Endres
 * @since 10-29-2018
 */
public interface PacketADT
{

    /**
     * Returns the session key to be used between sender and receiver.
     *
     * @return the session key
     */
    public BigInteger getSessionKey();

    /**
     * Sets the session key to the supplied key
     *
     * @param sessionKey The key to set
     */
    public void setSessionKey(BigInteger sessionKey);

    /**
     * Returns the message
     *
     * @return the message
     */
    public BigInteger getMessage();

    /**
     * Sets the message contents
     *
     * @param message The message to set
     */
    public void setMessage(BigInteger message);

    /**
     * Creates an error in the message
     *
     * @param error The error to insert
     */
    public void setErrorInMessage(BigInteger error);

    /**
     * Returns the signature
     *
     * @return The signature
     */
    public BigInteger getSignature();

    /**
     * Sets the signature to the supplied signature
     *
     * @param signature The signature to set
     */
    public void setSignature(BigInteger signature);

    /**
     * Returns a String representation of the packet
     *
     * @return A String representation of the packet
     */
    public String toString();
}
