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

            //BEGIN HANDSHAKING HERE
            //Send Cipher Suite
            BigInteger ciphers = ASCII.StringtoBigInt("1,2,3");
            Packet packet = new Packet(NONCE, ciphers);
            PACKETS.add(packet);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Get Cipher Choice and Public Key
            String packetString = incoming.readLine();
            packet = getPacket(packetString);
            PACKETS.add(packet);
            BigInteger serverNonce = packet.getSessionKey();
            BigInteger messageInt = packet.getMessage();

            System.out.println("Received: " + packetString);

            String[] message = ASCII.BigIntToString(messageInt).split(";");
            String choice = message[0];
            String nonceString = message[1];
            String keyString = message[2];

            RSAKey serverPublicKey = keyFromString(keyString);

            System.out.println("Choice: " + choice);
            System.out.println("Encrypted Nonce: " + nonceString);
            System.out.println("Key: " + serverPublicKey.toString());

            //Verify Nonce
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

            BigInteger pms = BigInteger.valueOf(Math.abs(RAND.nextInt()));
            BigInteger encryptedPMS = serverPublicKey.crypt(pms);

            //Send
            packet = new Packet(NONCE, encryptedPMS);
            PACKETS.add(packet);
            System.out.println("Sending PMS to client: " + pms);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Create Encryption Keys
            BigInteger encryptionBase = pms.multiply(NONCE).multiply(serverNonce);
            int factorInt = 2;
            BigInteger factor = BigInteger.valueOf(factorInt);
            BigInteger Kc = encryptionBase.divide(factor);
            BigInteger Mc = Kc.pow(factorInt);
            BigInteger Ks = Mc.multiply(factor);
            BigInteger Ms = Ks.nextProbablePrime();

            System.out.println("Product:\t" + encryptionBase);
            System.out.println("Kc:\t" + Kc);
            System.out.println("Mc:\t" + Mc);
            System.out.println("Ks:\t" + Ks);
            System.out.println("Ms:\t" + Ms);

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

            //Send MACc
            packet = new Packet(NONCE, MACc);
            outgoing.println(preparePacket(packet));
            outgoing.flush();

            //Receive MACs
            String MACs_rec = incoming.readLine();
            packet = getPacket(MACs_rec);
            System.out.println("Received MACs: " + packet.getMessage());

            if (MACs.equals(packet.getMessage()))
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
            e.printStackTrace();
            return;
        }

        /* Exchange messages with the other end of the connection until one side or 
         the other closes the connection.  This client program send the first message.
         After that,  messages alternate strictly back and forth. */
        try
        {
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
                outgoing.println(MESSAGE + messageOut);
                outgoing.flush();
                if (outgoing.checkError())
                {
                    throw new IOException("Error occurred while transmitting message.");
                }
                System.out.println("WAITING...");
                messageIn = incoming.readLine();
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
                }
                System.out.println("RECEIVED:  " + messageIn);
            }
        }
        catch (Exception e)
        {
            System.out.println("Sorry, an error has occurred.  Connection lost.");
            System.out.println(e.toString());
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

} //end class ChatClient
