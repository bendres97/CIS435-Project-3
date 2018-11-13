package Network;

import Cryptography.*;
import java.math.BigInteger;

/**
 * <p>
 * The driver for this project.
 *
 * @author Bryan Endres
 * @since 10-29-2018
 */
public class SecureMessageSystem
{

    private static final int CASE1 = 1;
    private static final int CASE2 = 2;
    private static final int CASE3 = 3;
    private static final int CASE4 = 4;
    private static final int CASE5 = 5;

    private static final AsciiConverter ASCII = new AsciiConverter();

    /**
     * The driver for this project.
     *
     * @param args Unused
     */
    public static void main(String[] args)
    {
        Sender amy = new Sender();
        Receiver bob = new Receiver();
        Network net = new Network();

        //Iterate for each test case
        for (int x = 1; x <= 10; x++)
        {
            int testCase = x;
            int errors = 0;

            //Run with no errors first time through, then add errors to transport.
            if (x > 5)
            {
                errors = 1;
                testCase -= 5;
            }

            System.out.println("\n-----Testing Case " + testCase + "-----");
            Packet packet = amy.getPacket(testCase, net, bob);
            System.out.println("The test packet to be sent to network is:" + packet.toString());

            System.out.println("------Sender sends the test packet to Receiver through internet------");

            net.sendToReceiver(packet);

            System.out.println("|||||||||||||||||||||||||||||||||||||||||||||");
            System.out.println("|||||||||||||||||||||||||||||||||||||||||||||");

            //Sets erros in connection as determined earlier.
            net.setInternetCondition(errors);

            //Determine print condition based on the number of errors
            if (errors < 0)
            {
                System.out.println("------Assume perfect Internet with no error------");
            }
            else
            {
                System.out.println("------Assume Internet with " + errors + " errors------");
            }

            System.out.println("|||||||||||||||||||||||||||||||||||||||||||||");
            System.out.println("|||||||||||||||||||||||||||||||||||||||||||||");

            System.out.println("------Receiver receives the test packet through network------");

            Packet rec = bob.receive(net);

            //Decrypt Key from Certificate
            RSAKey recKey = bob.getCertificate().getUserKey();
            RSAKey CAKey = net.CA.getPublicKey();

            BigInteger n = recKey.getN().modPow(CAKey.getEXP(), CAKey.getN());
            BigInteger exp = recKey.getEXP().modPow(CAKey.getEXP(), CAKey.getN());

            recKey = new RSAKey(n, exp);

            //Get and decrypt message
            BigInteger message = rec.getMessage();
            BigInteger decMsg = bob.decryptMessage(message);

            //Get the Digital Signature
            BigInteger signature = rec.getSignature();

            //Check the integrity of the message, only decrypt if authentic.
            if (net.MAC.checkIntegrity(decMsg, amy.getSecret()) && net.DS.authenticate(signature, message))
            {
                String msgString = ASCII.BigIntToString(decMsg).substring(1);
                decMsg = ASCII.StringtoBigInt(msgString);

                System.out.println("Message is authentic");
                String result = "";
                switch (testCase)
                {
                    //ShiftCipher + RSA + MAC+ Digital Signature + CA
                    case CASE1:
                        ShiftCipher shiftCipher = new ShiftCipher();
                        result = ASCII.BigIntToString(shiftCipher.Decrypt(decMsg, ASCII.StringtoBigInt(amy.getSecret())));
                        break;

                    //SubsitutionCipher + RSA + Digital Signature + MAC + CA
                    case CASE2:
                        SubstitutionCipher subCipher = new SubstitutionCipher();
                        result = subCipher.Decrypt(ASCII.BigIntToString(decMsg), net.getSubKey());
                        break;

                    //PolyalphabeticCipher + RSA +Digital Signature + MAC + CA
                    case CASE3:
                        PolyalphabeticCipher polyCipher = new PolyalphabeticCipher();
                        result = polyCipher.Decrypt(ASCII.BigIntToString(decMsg), amy.getSecret());
                        break;

                    //CBC + RSA + MAC + Digital Signature + CA
                    case CASE4:
                        CipherBlockChain cbc = new CipherBlockChain();
                        result = cbc.Decrypt(ASCII.BigIntToString(decMsg), net.getIV());
                        break;

                    //Block Cipher + RSA + MAC + Digital Signature + CA
                    case CASE5:
                        BlockCipher block = new BlockCipher();
                        result = block.Decrypt(ASCII.BigIntToString(decMsg));
                        break;
                }

                System.out.println("Decrypted Result: " + result);

            }
            else
            {
                System.out.println("Message is not authentic");
            }
        }
    }
}
