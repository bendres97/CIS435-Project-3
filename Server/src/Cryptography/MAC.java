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
    public BigInteger authenticate(BigInteger message, BigInteger secret)
    {
		String msg = ASCII.BigIntToString(message);
		String sec = ASCII.BigIntToString(secret);

		System.out.println("This is a secret: " + sec);

		//Concatenates the message and the secret
		String con = sec + msg;
		System.out.println("I concatinated this: " + con);

		//Hashing the message with the secret
		BigInteger concatenate = ASCII.StringtoBigInt(con);
	
		
		BigInteger moding = concatenate.mod(HASH);
		
		//Converting moding using ascii converter
		
		BigInteger big = ASCII.StringtoBigInt((char) moding.intValue() + msg);

		return big;
    }

    @Override
    public boolean checkIntegrity(BigInteger message, BigInteger secret)
    {				
		String msg = ASCII.BigIntToString(message);
		//takes out the hash from message
		msg = msg.substring(1);

		//places the hash into BigInteger form to encrypt MAC
		BigInteger MACEncrypt = authenticate(ASCII.StringtoBigInt(msg), secret);

		return MACEncrypt.equals(message);
    }
}
