package Cryptography;

import java.math.BigInteger;

/**
 * Message Authentication code stores a hash and ASCII converter for use with
 * authentication and integrity checks.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class MAC implements MACADT
{

    private final BigInteger HASH;
    private final static AsciiConverter ASCII = new AsciiConverter();
    ;
    private final static int HASH_KEY = 128;

    public MAC()
    {
        HASH = new BigInteger(String.valueOf(HASH_KEY));
    }

    @Override
    public BigInteger authenticate(String msg, String secret)
    {
        //Concatenate msg and secret and convert to BigInteger 
        BigInteger concatenation = ASCII.StringtoBigInt(secret + msg);

        //Mod the concatenation by the hash value
        BigInteger hashedValue = concatenation.mod(HASH);

        //Concatenate the new hash onto the string
        BigInteger mac = ASCII.StringtoBigInt((char) hashedValue.intValue() + msg);

        return mac;
    }

    public BigInteger authenticate(BigInteger msg, BigInteger secret)
    {
        String msgString = ASCII.BigIntToString(msg);
        String secretString = ASCII.BigIntToString(secret);

        return authenticate(msgString, secretString);
    }

    @Override
    public boolean checkIntegrity(BigInteger msg, String secret)
    {
        //Convert the message to a string and drop off the hashed secret
        String message = ASCII.BigIntToString(msg);
        message = message.substring(1); //Drop off secret on front of message

        //Call authenticate to rehash the message
        BigInteger check = authenticate(message, secret);

        //Check the integrity of the received msg
        return check.equals(msg);
    }

}
