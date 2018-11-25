package Cryptography;


import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
* Uses MAC to check the integrity of a message
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
public class MAC implements MACADT {

	private BigInteger hash;
	private final int mod = 13;

	/**
	 * The constructor for MAC
	 */
	public MAC() {
		//establishes the mod
		hash = new BigInteger(String.valueOf(mod));
	}

	/**
	 * This is the encrypt for MAC
	 * @param message
	 * 		Biginteger that is a message from the tester
	 * @param secret
	 * 		BigInteger that is the secret from the tester
	 * @return a biginteger that is manipulated by using the char ascii table
	 * 
	 */
	@Override
	public BigInteger mACEncrypt(BigInteger message, BigInteger secret) {
		AsciiConverter asciiConverter = new AsciiConverter();

		String msg = asciiConverter.BigIntToString(message);
		String sec = asciiConverter.BigIntToString(secret);

		//Concatenates the message and the secret
		String con = sec + msg;
		//Hashing the message with the secret
		BigInteger concatenate = asciiConverter.StringtoBigInt(con);
	
		
		BigInteger moding = concatenate.mod(hash);
		
		//Converting moding using ascii converter
		
		BigInteger big = asciiConverter.StringtoBigInt((char) moding.intValue() + msg);

		return big;
	}
	/**
	 * This is the MACChecker for MAC
	 * 
	 * @param message
	 * 		takes the message fromt the tester
	 * @param secret
	 * 		takes the secret from  the tester
	 * 
	 * @return a boolean to see if macencrypt equals the message
	 */
	@Override
	public boolean mACChecker(BigInteger message, BigInteger secret) {
		
		AsciiConverter asciiConverter = new AsciiConverter();
				
		String msg = asciiConverter.BigIntToString(message);
		//takes out the hash from message
		msg = msg.substring(1);

		//places the hash into BigInteger form to encrypt MAC
		BigInteger MACEncrypt = mACEncrypt(asciiConverter.StringtoBigInt(msg), secret);

		return MACEncrypt.equals(message);

	}

}
