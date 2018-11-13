package Network;

import Cryptography.Certificate;
import Cryptography.RSA;
import Cryptography.RSAKey;
import java.math.BigInteger;

/**
 * Acts as a simulator for a Receiver on Network
 *
 * @author Bryan Endres
 * @since 10-29-2018
 */
public class Receiver implements ReceiverADT
{

    private Packet rcvPacket;

    private final Certificate CERT;
    private final RSA RSA;

    /**
     * Constructs a Receiver that contain a default packet.
     */
    public Receiver()
    {
        System.out.println("----- Receiver is created -------");

        rcvPacket = new Packet();

        //2048 bits ensures that message can be properly encoded/decoded.
        RSA = new RSA(2048);

        Network.CA.register(this);
        CERT = Network.CA.getCertificate(this);
    }

    /**
     * Receives a packet from the given network
     *
     * @param net The network to get the packet from
     */
    @Override
    public Packet receive(Network net)
    {
        System.out.println("Receiver Receives the packet from Internet");
        rcvPacket = net.receiveFromSender();

        System.out.println("Packet is: " + rcvPacket.toString());

        return rcvPacket;
    }

    @Override
    public Certificate getCertificate()
    {
        return CERT;
    }

    @Override
    public RSAKey getPublicKey()
    {
        return RSA.getPublicKey();
    }

    @Override
    public BigInteger decryptMessage(BigInteger message)
    {
        RSAKey privateKey = RSA.getPrivateKey();
        return message.modPow(privateKey.getEXP(), privateKey.getN());
    }
}
