package Network;

/**
 * Acts as a simulator of a Network
 *
 * @author Bryan Endres
 * @since 10-29-2018
 */
import Cryptography.*;
import java.math.BigInteger;
import java.util.Random;

public class Network implements NetworkADT
{

    private Packet inFromSender, outToReceiver;

    //Global CA to simulate a CA being available to all of the Internet
    public static final CertificateAuthority CA = new CertificateAuthority();
    public static final MAC MAC = new MAC();
    public static final DigitalSignature DS = new DigitalSignature();

    private final String IV;
    private final char[] SUB_KEY;

    /**
     * Constructs a network with two empty packets.
     */
    public Network()
    {
        System.out.println("----Network is created-----");
        inFromSender = new Packet();
        outToReceiver = new Packet();

        //Randomly create IV
        Random rand = new Random();
        String iv = "";
        for (int n = 0; n < 3; n++)
        {
            iv += rand.nextBoolean() ? "1" : "0";
        }

        IV = iv;

        //Creates Substitution Key
        char[] substitutionKey = new char[128];
        for (int n = 0; n < substitutionKey.length; n++)
        {
            substitutionKey[n] = (char) n;
        }

        //Randomly shuffle the array.
        Random shuffler = new Random();
        for (int n = 0; n < 10000; n++)
        {
            int index1 = shuffler.nextInt(substitutionKey.length);
            int index2 = shuffler.nextInt(substitutionKey.length);

            //Swap
            char temp = substitutionKey[index1];
            substitutionKey[index1] = substitutionKey[index2];
            substitutionKey[index2] = temp;
        }

        SUB_KEY = substitutionKey;
    }

    /**
     * Sends the given packet to a receiver on the network
     *
     * @param pk the packet to send
     */
    @Override
    public void sendToReceiver(Packet pk)
    {
        inFromSender = pk;
    }

    /**
     * Creates the specified error in the packet, or none of error is zero.
     *
     * @param error the error
     */
    @Override
    public void setInternetCondition(int error)
    {
        if (error == 0)
        {
            outToReceiver = inFromSender;
        }
        else
        {
            inFromSender.setErrorInMessage(new BigInteger(Integer.toString(error)));
            outToReceiver = inFromSender;
        }
    }

    /**
     * Receive a packet from a sender.
     *
     * @return The packet from a sender
     */
    @Override
    public Packet receiveFromSender()
    {
        return outToReceiver;
    }

    public String getIV()
    {
        return IV;
    }

    public char[] getSubKey()
    {
        return SUB_KEY;
    }
}
