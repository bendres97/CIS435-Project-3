package SSL;

import Cryptography.*;
import Network.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * This program is one end of a simple command-line interface chat program. It
 * acts as a server which waits for a connection from the ChatClient program.
 * The port on which the server listens can be specified as a command-line
 * argument. This program only supports one connection. As soon as a connection
 * is opened, the listening socket is closed down. The two ends of the
 * connection each send a HANDSHAKE string to the other, so that both ends can
 * verify that the program on the other end is of the right type. Then the
 * connected programs alternate sending messages to each other. The client
 * always sends the first message. The user on either end can close the
 * connection by entering the string "quit" when prompted for a message. Note
 * that the first character of any string sent over the connection must be 0 or
 * 1; this character is interpreted as a command for security purpose
 */
public class ChatServer
{

    /**
     * Port to listen on, if none is specified on the command line.
     */
    static final int DEFAULT_PORT = 1728;

    /**
     * Handshake string. Each end of the connection sends this string to the
     * other just after the connection is opened. This is done to confirm that
     * the program on the other side of the connection is a ChatClient program.
     */
    static final String HANDSHAKE = "CIS435535";

    /**
     * This character is prepended to every message that is sent.
     */
    static final char MESSAGE = '0'; //more like the type in SSL

    /**
     * This character is sent to the connected program when the user quits.
     */
    static final char CLOSE = '1'; //more like the type in SSL

    static final Random RAND = new Random();
    static final BigInteger NONCE = BigInteger.valueOf(Math.abs(RAND.nextInt()));
    static final AsciiConverter ASCII = new AsciiConverter();
    static final String[] CIPHERS =
    {
        "1", "3", "5"
    };
    static RSA RSA = new RSA();
    static RSAKey PUBLIC_KEY = RSA.getPublicKey();
    static RSAKey PRIVATE_KEY = RSA.getPrivateKey();
    static final ArrayList<Packet> PACKETS = new ArrayList<>();
    static final MAC MAC = new MAC();

    //Case Variables
    private static final int CASE1 = 1;
    private static final int CASE2 = 2;
    private static final int CASE3 = 3;
    private static final int CASE4 = 4;
    private static final int CASE5 = 5;

    static String IV;
    static char[] SUB_KEY;

    public static void main(String[] args)
    {

        int port = DEFAULT_PORT;   // The port on which the server listens.

        ServerSocket listener;  // Listens for a connection request.
        Socket connection;      // For communication with the client.

        BufferedReader incoming;  // Stream for receiving data from client.
        PrintWriter outgoing;     // Stream for sending data to client.
        String messageOut;        // A message to be sent to the client.
        String messageIn;         // A message received from the client.

        BufferedReader userInput; // A wrapper for System.in, for reading
        // lines of input from the user.

        /* Wait for a connection request.  When it arrives, close
           down the listener.  Create streams for communication
           and exchange the handshake. */
        String choice;
        BigInteger Kc;
        BigInteger Ks;
        RSAKey clientPublicKey;
        try
        {
            listener = new ServerSocket(port);
            System.out.println("Listening on port " + listener.getLocalPort());
            connection = listener.accept();
            listener.close();
            incoming = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
            outgoing = new PrintWriter(connection.getOutputStream());
            outgoing.println(HANDSHAKE);  // Send handshake to client.
            outgoing.flush();
            messageIn = incoming.readLine();  // Receive handshake from client.

            if (!HANDSHAKE.equals(messageIn))
            {
                throw new Exception("Connected program is not a ChatClient!");
            }
            /////////////////////////////////////////////////////
            //Start of handshake////////////////////////////////
            ////////////////////////////////////////////////////

            //Receive cipher suite
            String packetString = incoming.readLine();
            Packet packet = getPacket(packetString);
            PACKETS.add(packet);
            System.out.println("Received:\t" + packetString);
            System.out.println("Packet:\t" + packet);

            System.out.println("Server supports the following cipher suites:");
            System.out.println("Case 1: ShiftCipher + RSA + MAC"
                    + "\n\t" + "Case 2: PolyalphabeticCipher + RSAMAC"
                    + "\n\t" + "Case 5: Block Cipher + RSA + MAC");
            System.out.println();

            String[] packetDelimited = ASCII.BigIntToString(packet.getMessage()).split(";");
            String ciphers = packetDelimited[0];
            String clientKeyString = packetDelimited[1];
            clientPublicKey = keyFromString(clientKeyString);

            String[] clientCiphers = ciphers.split(",");
            System.out.println("Ciphers: " + Arrays.toString(clientCiphers));
            System.out.println();
            choice = "";
            int i = 0;

            String pick[] = new String[2];
            //Pick a cipher
            for (String cipher : clientCiphers)
            {

                for (String CIPHER : CIPHERS)
                {
                    if (cipher.equals(CIPHER))
                    {
                        pick[i] = cipher;
                        i++;
                    }
                }
            }

            choice += pick[(new Random()).nextInt(pick.length)];

            //If no cipher is found
            if (choice.equals(""))
            {
                System.out.println("ERROR: This client is not supported");
                connection.close();
                System.exit(1);
            }

            //Encrypt NONCE and send choice back along with public key
            BigInteger clientNonce = packet.getSessionKey();
            BigInteger encryptedNonce = PRIVATE_KEY.crypt(clientNonce);
            String keyString = keyToString(PUBLIC_KEY);
            String nonceString = encryptedNonce.toString();
            BigInteger message = ASCII.StringtoBigInt(choice + ';' + nonceString + ';' + keyString);
            packet = new Packet(NONCE, message);
            PACKETS.add(packet);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Receive Pre Master Secret
            String pmsString = incoming.readLine();
            System.out.println("Received: " + pmsString);
            System.out.println();

            packet = getPacket(pmsString);
            PACKETS.add(packet);
            BigInteger pmsInt = packet.getMessage();
            BigInteger pms = PRIVATE_KEY.crypt(pmsInt);

            System.out.println("PMS: " + pms);
            System.out.println();

            //Create Encryption Keys
            BigInteger encryptionBase = pms.multiply(NONCE).multiply(clientNonce);
            int factorInt = 2;
            BigInteger factor = BigInteger.valueOf(factorInt);
            Kc = encryptionBase.divide(factor);
            BigInteger Mc = Kc.pow(factorInt);
            Ks = Mc.multiply(factor);
            BigInteger Ms = Ks.nextProbablePrime();

            System.out.println("Product:\t" + encryptionBase);
            System.out.println("Kc:\t" + Kc);
            System.out.println("Mc:\t" + Mc);
            System.out.println("Ks:\t" + Ks);
            System.out.println("Ms:\t" + Ms);
            System.out.println();

            //Calculate MAC values
            BigInteger packetSum = BigInteger.ZERO;
            for (Packet pkt : PACKETS)
            {
                packetSum = packetSum.add(pkt.getHashSum());
            }

            BigInteger MACc = packetSum.mod(Mc);
            BigInteger MACs = packetSum.mod(Ms);

            System.out.println("MACc: " + MACc);
            System.out.println("MACs: " + MACs);
            System.out.println();

            //Send MACc
            packet = new Packet(NONCE, MACs);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Receive MACc
            String MACc_rec = incoming.readLine();
            packet = getPacket(MACc_rec);
            System.out.println("Received MACc: " + packet.getMessage());
            System.out.println();

            if (MACc.equals(packet.getMessage()))
            {
                System.out.println("MAC check is equal. Secure connection established.");
            }

            else
            {
                System.out.println("ERROR: Insecure connection. Aborting");
                connection.close();
                System.exit(1);
            }
        }
        catch (Exception e)
        {
            System.out.println("An error occurred while opening connection.");
            System.out.println(e.toString());
            return;
        }

        /* Exchange messages with the other end of the connection until one side
         or the other closes the connection.  This server program waits for 
         the first message from the client.  After that, messages alternate 
         strictly back and forth. */
        try
        {
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
            userInput = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("NOTE: Enter 'quit' to end the program.\n");
            while (true)
            {
                System.out.println("WAITING...");
                messageIn = incoming.readLine();
                String recMsg = messageIn;
                if (messageIn.length() > 0)
                {
                    // The first character of the message is a command. If 
                    // the command is CLOSE, then the connection is closed.  
                    // Otherwise, remove the command character from the 
                    // message and procede.
                    if (messageIn.charAt(0) == CLOSE)
                    {
                        System.out.println("Connection closed at other end.");
                        connection.close();
                        break;
                    }

                    messageIn = messageIn.substring(1);
                    Packet packet = getPacket(messageIn);
                    System.out.println("This is the packet that is taken in: " + packet);
                    recMsg = getMessage(packet, Kc, Integer.valueOf(choice));

                }
                System.out.println("RECEIVED:  " + recMsg);
                System.out.println();

                System.out.print("SEND:      ");
                messageOut = userInput.readLine();
                if (messageOut.equalsIgnoreCase("quit"))
                {
                    // User wants to quit.  Inform the other side
                    // of the connection, then close the connection
                    outgoing.println(CLOSE);
                    outgoing.flush();  // Make sure the data is sent!
                    connection.close();
                    System.out.println("Connection closed.");
                    break;
                }
                Packet packet = getMessagePacket(messageOut, Integer.valueOf(choice), Ks, clientPublicKey);
                outgoing.println(MESSAGE + preparePacket(packet));
                outgoing.flush();
                if (outgoing.checkError())
                {
                    throw new IOException("Error occurred while transmitting message.");
                }
            }
        }
        catch (Exception e)
        {
            System.out.println("Sorry, an error has occurred.  Connection lost.");
            System.out.println("Error:  " + e);
            System.exit(1);
        }

    }

    /**
     * Converts a given string into a packet object.
     *
     * @author Bryan Endres
     * @author Andrew Bradley
     * @param incoming the String to convert
     * @return a Packet
     */
    public static Packet getPacket(String incoming)
    {
        String[] packetString = incoming.split(";");

        BigInteger sessionKey = new BigInteger(packetString[0]);
        BigInteger message = new BigInteger(packetString[1]);
        BigInteger signature = new BigInteger(packetString[2]);

        return new Packet(sessionKey, message, signature);
    }

    /**
     * Converts a given packet to a String that can be sent over a network.
     *
     * @author Bryan Endres
     * @author Andrew Bradley
     * @param packet The packet
     * @return a String
     */
    public static String preparePacket(Packet packet)
    {
        String packetString = "";
        packetString += packet.getSessionKey().toString() + ';';
        packetString += packet.getMessage().toString() + ';';
        packetString += packet.getSignature().toString() + ';';

        return packetString;
    }

    /**
     * Converts an RSA Key to a String representation
     *
     * @author Bryan Endres
     * @author Andrew Bradley
     * @param key The RSAKey
     * @return the String Representation
     */
    public static String keyToString(RSAKey key)
    {
        return key.getEXP().toString() + "_" + key.getN().toString();
    }

    /**
     * Converts an RSA Key String to an RSAKey
     *
     * @author Bryan Endres
     * @author Andrew Bradley
     * @param keyString The string to convert
     * @return The RSAKey
     */
    public static RSAKey keyFromString(String keyString)
    {
        String[] keys = keyString.split("_");
        BigInteger exp = new BigInteger(keys[0]);
        BigInteger n = new BigInteger(keys[1]);

        return new RSAKey(n, exp);
    }

    public static Packet getMessagePacket(String message, int testCase, BigInteger Ks, RSAKey clientPublicKey)
    {
        String secret = ASCII.BigIntToString(Ks);
        BigInteger msg = ASCII.StringtoBigInt(message);
        switch (testCase)
        {
            //ShiftCipher + RSA + MAC+ Digital Signature + CA
            case CASE1:
                ShiftCipher shiftCipher = new ShiftCipher();
                msg = shiftCipher.Encrypt(msg, ASCII.StringtoBigInt(secret));
                break;

            //SubsitutionCipher + RSA + Digital Signature + MAC + CA
            case CASE2:
                SubstitutionCipher subCipher = new SubstitutionCipher();
                msg = ASCII.StringtoBigInt(subCipher.Encrypt(message, SUB_KEY));
                break;

            //PolyalphabeticCipher + RSA +Digital Signature + MAC + CA
            case CASE3:
                PolyalphabeticCipher polyCipher = new PolyalphabeticCipher();
                msg = ASCII.StringtoBigInt(polyCipher.Encrypt(message, secret));
                break;

            //CBC + RSA + MAC + Digital Signature + CA
            case CASE4:
                CipherBlockChain cbc = new CipherBlockChain();
                msg = ASCII.StringtoBigInt(cbc.Encrypt(message, IV));
                break;

            //Block Cipher + RSA + MAC + Digital Signature + CA
            case CASE5:
                BlockCipher block = new BlockCipher();
                msg = ASCII.StringtoBigInt(block.Encrypt(message));
                break;

            //Default Case - Bad data is entered
            default:
                System.out.println("You have entered an invalid case");
                return null;
        }

        //MAC
        message = ASCII.BigIntToString(msg);
        message = ASCII.BigIntToString(MAC.authenticate(message, secret));

        //Encrypt with RSA
        msg = ASCII.StringtoBigInt(message);
        msg = msg.modPow(clientPublicKey.getEXP(), clientPublicKey.getN());

        return new Packet(NONCE, msg);
    }

    //Check the integrity of the message, only decrypt if authentic.
    public static String getMessage(Packet packet, BigInteger Kc, int testCase)
    {
        String secret = ASCII.BigIntToString(Kc);
        //Get and decrypt message
        BigInteger message = packet.getMessage();
        BigInteger decMsg = PRIVATE_KEY.crypt(message);

        String result = "";

        if (MAC.checkIntegrity(decMsg, secret))
        {
            String msgString = ASCII.BigIntToString(decMsg).substring(1);
            decMsg = ASCII.StringtoBigInt(msgString);

            System.out.println("Message is authentic");
            switch (testCase)
            {
                //ShiftCipher + RSA + MAC + Digital Signature + CA
                case CASE1:
                    ShiftCipher shiftCipher = new ShiftCipher();
                    result = ASCII.BigIntToString(shiftCipher.Decrypt(decMsg, ASCII.StringtoBigInt(secret)));
                    break;

                //SubsitutionCipher + RSA + Digital Signature + MAC + CA
                case CASE2:
                    SubstitutionCipher subCipher = new SubstitutionCipher();
                    result = subCipher.Decrypt(ASCII.BigIntToString(decMsg), SUB_KEY);
                    break;

                //PolyalphabeticCipher + RSA + MAC + CA
                case CASE3:
                    PolyalphabeticCipher polyCipher = new PolyalphabeticCipher();
                    result = polyCipher.Decrypt(ASCII.BigIntToString(decMsg), secret);
                    break;

                //CBC + RSA + MAC + Digital Signature + CA
                case CASE4:
                    CipherBlockChain cbc = new CipherBlockChain();
                    result = cbc.Decrypt(ASCII.BigIntToString(decMsg), IV);
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
            return "NOT AUTHENTIC";
        }

        return result;
    }

} //end class ChatServer
