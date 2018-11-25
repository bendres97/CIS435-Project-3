package Network;

import java.math.BigInteger;

/**
 * Defines the interface for the Sender class.
 *
 * @author Andrew Bradley
 * @author Bryan Endres
 * @since 10-29-2018
 */
public interface SenderADT
{

    /**
     * <p>
     * Returns the packet from the sender
     *
     * <p>
     * Generates and returns a message based on the given test case.
     *
     * <p>
     * 1: ShiftCipher + RSA + MAC+ Digital Signature + CA
     * <p>
     * 2: SubsitutionCipher + RSA + Digital Signature + MAC + CA
     * <p>
     * 3: PolyalphabeticCipher + RSA +Digital Signature + MAC + CA
     * <p>
     * 4: CBC + RSA + MAC + Digital Signature + CA
     * <p>
     * 5: Block Cipher + RSA + MAC + Digital Signature + CA
     *
     * @param net The network this packet will be sent to
     * @param testCase The test case to run
     * @return The packet from the sender
     */
    public Packet getPacket(int testCase, Network net, Receiver rec);

    /**
     * <p>
     * Generates and returns a message based on the given test case.
     *
     * <p>
     * 1: ShiftCipher + RSA + MAC+ Digital Signature + CA
     * <p>
     * 2: SubsitutionCipher + RSA + Digital Signature + MAC + CA
     * <p>
     * 3: PolyalphabeticCipher + RSA +Digital Signature + MAC + CA
     * <p>
     * 4: CBC + RSA + MAC + Digital Signature + CA
     * <p>
     * 5: Block Cipher + RSA + MAC + Digital Signature + CA
     *
     * @param net The network this packet will be sent to
     * @param testCase The case with which to generate the message
     * @return The generated message.
     */
    public BigInteger generateMessage(int testCase, Network net, Receiver rec);

    /**
     * Returns the secret
     *
     * @return The secret
     */
    public BigInteger getSecret();
}
