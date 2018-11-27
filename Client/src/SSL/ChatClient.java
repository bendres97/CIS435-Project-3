package SSL;

import Cryptography.*;
import Network.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.ArrayList;
import java.util.Random;

/**
 * This program is one end of a simple command-line interface chat program. It
 * acts as a client which makes a connection to a CLChatServer program. The
 * computer to connect to must be given as a command-line argument to the
 * program. The two ends of the connection each send a HANDSHAKE string to the
 * other, so that both ends can verify that the program on the other end is of
 * the right type. Then the connected programs alternate sending messages to
 * each other. The client always sends the first message. The user on either end
 * can close the connection by entering the string "quit" when prompted for a
 * message. Note that the first character of any string sent over the connection
 * must be 0 or 1; this character is interpreted as a command for security
 * purpose.
 *
 * @author Andrew Bradley
 * @author Bryan Endres
 *
 */
class ChatClient
{

    /**
     * Port number on server, if none is specified on the command line.
     */
    static final int DEFAULT_PORT = 1728;

    /**
     * Handshake string. Each end of the connection sends this string to the
     * other just after the connection is opened. This is done to confirm that
     * the program on the other side of the connection is a CLChat program.
     */
    static final String HANDSHAKE = "CIS435535";

    /**
     * This character is prepended to every message that is sent.
     */
    static final char MESSAGE = '0'; //more like the type in SSL

    /**
     * This character is sent to the connected program when the user quits.
     */
    static final char CLOSE = '1';  //more like the type in SSL

    static final Random RAND = new Random();
    static final BigInteger NONCE = BigInteger.valueOf(Math.abs(RAND.nextInt()));
    static final AsciiConverter ASCII = new AsciiConverter();
    static final RSA RSA = new RSA();
    static final ArrayList<Packet> PACKETS = new ArrayList<>();
    static final MAC MAC = new MAC();
    static final RSAKey PUBLIC_KEY = RSA.getPublicKey();
    static final RSAKey PRIVATE_KEY = RSA.getPrivateKey();

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

        String computer = "localhost";  // The computer where the server is running,
        // as specified on the command line.  It can
        // be either an IP number or a domain name.

        int port = DEFAULT_PORT;   // The port on which the server listens.

        Socket connection;      // For communication with the server.

        BufferedReader incoming;  // Stream for receiving data from server.
        PrintWriter outgoing;     // Stream for sending data to server.
        String messageOut;        // A message to be sent to the server.
        String messageIn;         // A message received from the server.

        BufferedReader userInput; // A wrapper for System.in, for reading
        // lines of input from the user.

        /* Open a connetion to the server.  Create streams for 
         communication and exchange the handshake. */
        BigInteger Kc;
        BigInteger Ks;
        String choice;
        RSAKey serverPublicKey;
        try
        {
            System.out.println("Connecting to " + computer + " on port " + port);
            connection = new Socket(computer, port);
            incoming = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
            outgoing = new PrintWriter(connection.getOutputStream());
            outgoing.println(HANDSHAKE);  // Send handshake to client.
            outgoing.flush();
            messageIn = incoming.readLine();  // Receive handshake from client.
            if (!messageIn.equals(HANDSHAKE))
            {
                throw new IOException("Connected program is not CLChat!");
            }
            System.out.println("Connected. Initiating Handshake");

            /////////////////////////////////////////////////////
            //Start of handshake////////////////////////////////
            ////////////////////////////////////////////////////
            //Step 1 of the handshake
            //Cases that the Client holds
            String ciphers = "1,2,3";

            //Client suports the following cipher suits
            System.out.println("Client supports the following cipher suites:");
            System.out.println("\tCase 1: ShiftCipher + RSA + MAC"
                    + "\n\t" + "Case 2: SubstitutionCipher + RSA + MAC"
                    + "\n\t" + "Case 3: PolyalphabeticCipher + RSA + MAC");
            System.out.println();

            //Taking the public key of the client and concatenating with ciphers key 
            String publicKeyString = keyToString(PUBLIC_KEY);
            String ciphers_Key = ciphers + ';' + publicKeyString;
            BigInteger ckInt = ASCII.StringtoBigInt(ciphers_Key);

            //Adds the cipher key and Client nonce into a packet
            Packet packet = new Packet(NONCE, ckInt);
            //Adds packet to array list
            PACKETS.add(packet);

            //Sends the packet to server
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Step 2 of the handshake
            //Get Cipher Choice and Public Key
            String packetString = incoming.readLine();
            packet = getPacket(packetString);

            //Adds packet into a queue
            PACKETS.add(packet);

            //Retrieves the message and server nonce from packet
            BigInteger serverNonce = packet.getSessionKey();
            BigInteger messageInt = packet.getMessage();

            System.out.println("Received: " + packetString);
            System.out.println();

            //Splits the message into the key, nonce and cipher suit choice
            String[] message = ASCII.BigIntToString(messageInt).split(";");
            choice = message[0];
            String nonceString = message[1];
            String keyString = message[2];

            serverPublicKey = keyFromString(keyString);

            System.out.println("Choice: " + choice);
            System.out.println("Encrypted Nonce: " + nonceString);
            System.out.println("Key: " + serverPublicKey.toString());
            System.out.println();

            //Step 3 of the handshake
            //Verify the nonce using the server's public key
            BigInteger encryptedNonce = new BigInteger(nonceString);
            BigInteger nonce = serverPublicKey.crypt(encryptedNonce);

            if (NONCE.equals(nonce))
            {
                System.out.println("Authentication Passed");
            }

            else
            {
                System.out.println("AUTHENTICATION FAILED");
                connection.close();
                System.exit(1);
            }

            //Creates premaster key
            BigInteger pms = BigInteger.valueOf(Math.abs(RAND.nextInt()));
            BigInteger encryptedPMS = serverPublicKey.crypt(pms);

            //Sends the nonce and encrypted pre master key
            packet = new Packet(NONCE, encryptedPMS);

            //put the packet into a list
            PACKETS.add(packet);
            System.out.println("Sending PMS to client: " + pms);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Step 4 of the handshake
            //Create Encryption Keys: Kc, Mc, Ks, Ms
            BigInteger encryptionBase = pms.multiply(NONCE).multiply(serverNonce);

            //All of the encryption keys are different values of Big Integers 
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

            //Step 5 of the handshake
            //Calculate the MAC values by using the Mc and Ms
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

            //Step 7 of the handshake
            //Send MACc to the server
            packet = new Packet(NONCE, MACc);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Receive MACs from the server
            String MACs_rec = incoming.readLine();
            packet = getPacket(MACs_rec);
            System.out.println("Received MACs: " + packet.getMessage());
            System.out.println();

            //Compares the MACs from the client and MACs from the server
            if (MACs.equals(packet.getMessage()))
            {
                System.out.println("MAC check is equal. Secure connection established.");
            }

            else
            {
                //If the MACs from the client and the MACs from the server don't equal each other,
                //aborting progam
                System.out.println("ERROR: Insecure connection. Aborting");
                connection.close();
                System.exit(1);
            }

        }
        catch (Exception e)
        {
            System.out.println("An error occurred while opening connection.");
            System.out.println(e.toString());
            e.printStackTrace();
            return;
        }

        /* Exchange messages with the other end of the connection until one side or 
         the other closes the connection.  This client program send the first message.
         After that,  messages alternate strictly back and forth. */
        try
        {
            //Randomly create IV that is 3 bits long
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
                System.out.print("SEND:      ");
                messageOut = userInput.readLine();
                if (messageOut.equalsIgnoreCase("quit"))
                {
                    // User wants to quit.  Inform the other side
                    // of the connection, then close the connection.
                    outgoing.println(CLOSE);
                    outgoing.flush();
                    connection.close();
                    System.out.println("Connection closed.");
                    break;
                }
                Packet packet = getMessagePacket(messageOut, Integer.valueOf(choice), Kc, serverPublicKey);
                outgoing.println(MESSAGE + preparePacket(packet));
                outgoing.flush();
                if (outgoing.checkError())
                {
                    throw new IOException("Error occurred while transmitting message.");
                }
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

                    //Takes the first part of messageIn
                    messageIn = messageIn.substring(1);
                    System.out.println("This is the packet that is taken in: " + messageIn);
                    packet = getPacket(messageIn);
                    recMsg = getMessage(packet, Ks, Integer.valueOf(choice));
                }
                System.out.println("RECEIVED:  " + recMsg);
                System.out.println();
            }
        }
        catch (Exception e)
        {
            System.out.println("Sorry, an error has occurred.  Connection lost.");
            System.out.println(e.toString());
            e.printStackTrace();
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

    /**
     * Encrypts the message using different forms of encryption then
     * authenticates using MAC before sending the code
     *
     * @author Bryan Endres
     * @author Andrew Bradley
     * @param message The message to convert
     * @param testCase the case to be used for authentication
     * @param Kc The secret key to use
     * @param serverPublicKey The public key for the server
     * @return a packet
     *
     */
    public static Packet getMessagePacket(String message, int testCase, BigInteger Kc, RSAKey serverPublicKey)
    {
        String secret = ASCII.BigIntToString(Kc);
        BigInteger msg = ASCII.StringtoBigInt(message);
        switch (testCase)
        {
            //ShiftCipher + RSA + MAC
            case CASE1:
                ShiftCipher shiftCipher = new ShiftCipher();
                msg = shiftCipher.Encrypt(msg, Kc);
                break;

            //SubsitutionCipher + RSA + MAC
            case CASE2:
                SubstitutionCipher subCipher = new SubstitutionCipher();
                msg = ASCII.StringtoBigInt(subCipher.Encrypt(message, SUB_KEY));
                break;

            //PolyalphabeticCipher + RSA + MAC
            case CASE3:
                PolyalphabeticCipher polyCipher = new PolyalphabeticCipher();
                msg = ASCII.StringtoBigInt(polyCipher.Encrypt(message, secret));
                break;

            //CBC + RSA + MAC
            case CASE4:
                CipherBlockChain cbc = new CipherBlockChain();
                msg = ASCII.StringtoBigInt(cbc.Encrypt(message, IV));
                break;

            //Block Cipher + RSA + MAC
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
        msg = msg.modPow(serverPublicKey.getEXP(), serverPublicKey.getN());

        return new Packet(NONCE, msg);
    }

    /**
     * Check the integrity of the message, only decrypt if MAC is authentic.
     *
     * @param packet The packet to retrieve the message from
     * @param Ks The client's secret
     * @param testCase The case to use for decryption
     * @return a string that gets printed out from either the client and server
     */
    public static String getMessage(Packet packet, BigInteger Ks, int testCase)
    {
        String secret = ASCII.BigIntToString(Ks);
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
                //ShiftCipher + RSA + MAC
                case CASE1:
                    ShiftCipher shiftCipher = new ShiftCipher();
                    result = ASCII.BigIntToString(shiftCipher.Decrypt(decMsg, Ks));
                    break;

                //SubsitutionCipher + RSA + MAC
                case CASE2:
                    SubstitutionCipher subCipher = new SubstitutionCipher();
                    result = subCipher.Decrypt(ASCII.BigIntToString(decMsg), SUB_KEY);
                    break;

                //PolyalphabeticCipher + RSA + MAC
                case CASE3:
                    PolyalphabeticCipher polyCipher = new PolyalphabeticCipher();
                    result = polyCipher.Decrypt(ASCII.BigIntToString(decMsg), secret);
                    break;

                //CBC + RSA + MAC
                case CASE4:
                    CipherBlockChain cbc = new CipherBlockChain();
                    result = cbc.Decrypt(ASCII.BigIntToString(decMsg), IV);
                    result = result.substring(1);   //Remove IV at front
                    break;

                //Block Cipher + RSA + MAC
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

}
