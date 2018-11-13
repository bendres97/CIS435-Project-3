package Network;

/**
 * Acts as the simulator for a Packet.
 *
 * @author Bryan Endres
 * @since 10-29-2018
 */
import java.math.BigInteger;

public class Packet implements PacketADT
{

    private BigInteger sessionKey;
    private BigInteger message;
    private BigInteger signature;

    /**
     * Constructs a packet contained all zeroes.
     */
    public Packet()
    {
        sessionKey = BigInteger.ZERO;
        message = BigInteger.ZERO;
        signature = BigInteger.ZERO;
    }

    /**
     * Creates a packet using the given information
     *
     * @param sessionKey The session key
     * @param message The contained message
     * @param signature The signature for the packet
     */
    public Packet(BigInteger sessionKey, BigInteger message, BigInteger signature)
    {
        this.sessionKey = sessionKey;
        this.message = message;
        this.signature = signature;
    }

    /**
     * Returns the session key
     *
     * @return the session key
     */
    @Override
    public BigInteger getSessionKey()
    {
        return sessionKey;
    }

    /**
     * Sets the session key to the provided key
     *
     * @param sessionKey the sessionKey to set
     */
    @Override
    public void setSessionKey(BigInteger sessionKey)
    {
        this.sessionKey = sessionKey;
    }

    /**
     * Returns a BigInteger representation of the message
     *
     * @return the message
     */
    @Override
    public BigInteger getMessage()
    {
        return message;
    }

    /**
     * Sets the message to the given message
     *
     * @param message the message to set
     */
    @Override
    public void setMessage(BigInteger message)
    {
        this.message = message;
    }

    /**
     * Puts an error in the message
     *
     * @param error
     */
    @Override
    public void setErrorInMessage(BigInteger error)
    {
        this.message = this.message.add(error);
    }

    /**
     * Gets the signature from the packet
     *
     * @return the signature
     */
    @Override
    public BigInteger getSignature()
    {
        return signature;
    }

    /**
     * Sets the signature of the packet
     *
     * @param signature The signature to set
     */
    @Override
    public void setSignature(BigInteger signature)
    {
        this.signature = signature;
    }

    /**
     * Returns a String representation of the packet.
     *
     * @return A String representation of the packet.
     */
    @Override
    public String toString()
    {

        String result = "\n";

        result = result + "\tpk.message\t'Ks(m)' = " + this.message.toString()
                + "\n\tpk.signature\t'Ks(Ka-(H(m)))' = " + this.signature.toString()
                + "\n\tpk.sessionKey\t'Kb+(Ks)' = " + this.sessionKey.toString();

        return result;
    }
}
