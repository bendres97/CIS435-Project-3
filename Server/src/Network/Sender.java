package Network;

/**
 * <p>
 * Simulates the role of the sender in a Network.
 *
 * @author Bryan Endres
 * @since 10-29-2018
 */
import Cryptography.*;
import java.math.BigInteger;
import java.util.Random;

public class Sender implements SenderADT
{

    //Case Variables
    private static final int CASE1 = 1;
    private static final int CASE2 = 2;
    private static final int CASE3 = 3;
    private static final int CASE4 = 4;
    private static final int CASE5 = 5;

    //Used for converting between String and BigInteger
    private static final AsciiConverter ASCII = new AsciiConverter();

    //Universal secret to be used for certain methods
    private final BigInteger SECRET = ASCII.StringtoBigInt("CIS435");

    /**
     * Returns a sender with a pre-propagated packet.
     */
    public Sender()
    {
        System.out.println("----Sender is created-----");
    }

    /**
     * Returns the packet created in the constructor
     *
     * @param testCase The case to test
     * @param net The network this packet is for
     * @return The packet created in the constructor
     */
    @Override
    public Packet getPacket(int testCase, Network net, Receiver rec)
    {
        BigInteger message = generateMessage(testCase, net, rec);

        Random rand = new Random();
        BigInteger sessionKey = new BigInteger(String.valueOf(Math.abs(rand.nextInt())));
        Signature sig = net.DS.sign(ASCII.BigIntToString(message));
        BigInteger signature = sig.getEncryptedHash();

        return new Packet(sessionKey, message, signature);
    }

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
    @Override
    public BigInteger generateMessage(int testCase, Network net, Receiver rec)
    {
        String message = "This is the plaintext message."; 
        BigInteger msg = ASCII.StringtoBigInt(message);
        switch (testCase)
        {
            //ShiftCipher + RSA + MAC+ Digital Signature + CA
            case CASE1:
                ShiftCipher shiftCipher = new ShiftCipher();
                msg = shiftCipher.encrypt(msg, SECRET);
                break;

            //SubsitutionCipher + RSA + Digital Signature + MAC + CA
            case CASE2:
                SubsitutionCipher subCipher = new SubsitutionCipher();
                msg = subCipher.encrypt(message, net.getSubKey());
                break;

            //PolyalphabeticCipher + RSA +Digital Signature + MAC + CA
            case CASE3:
                PolyalphabeticCipher polyCipher = new PolyalphabeticCipher();
                msg = ASCII.StringtoBigInt(polyCipher.encrypt(msg, SECRET));
                break;

            //CBC + RSA + MAC + Digital Signature + CA
            case CASE4:
                CipherBlockChaining cbc = new CipherBlockChaining();
                msg = ASCII.StringtoBigInt(cbc.encrypt(msg, net.getIV()));
                break;

            //Block Cipher + RSA + MAC + Digital Signature + CA
            case CASE5:
                BlockCipher block = new BlockCipher();
                msg =block.encrypt(msg);
                break;

            //Default Case - Bad data is entered
            default:
                System.out.println("You have entered an invalid case");
                return null;
        }

        //MAC
      //  message = ASCII.BigIntToString(msg);
        msg = net.MAC.mACEncrypt(msg, SECRET);

        //Encrypt with RSA
        msg = ASCII.StringtoBigInt(message);
        RSAKey recKey = rec.getPublicKey();
        msg = msg.modPow(recKey.getEXP(), recKey.getN());

        return msg;
    }

    /**
     * Returns the secret
     *
     * @return The secret
     */
    @Override
    public BigInteger getSecret()
    {
        return SECRET;
    }
}
