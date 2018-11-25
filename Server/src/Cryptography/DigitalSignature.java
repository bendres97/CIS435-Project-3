package Cryptography;


import java.math.BigInteger;
import javafx.util.Pair;


/**
*
*
* Checks the digital signature of a the user who was sending the message
* It was to ensure authentication 
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
public class DigitalSignature implements DigitalSignatureADT{
	private BigInteger hash;
	private final int MOD = 128;
	private RSA1 rsa; 
	/**
	 * The constructor for Digital Signature
	 * Establishes the hash variable and rsa class
	 */
	public DigitalSignature() {
		//creates the hash
		hash = new BigInteger(String.valueOf(MOD));
		rsa = new RSA1();
	}

	/**
	 * Encrypts the message
	 * @param a message taken from the tester
	 * @return a pair of BigInteger
	 * 		that is the message and a pubKey
	 */
	@Override
	public Pair<BigInteger, BigInteger> encryptMessageDigest(BigInteger message) {
		
    	//mods the message with the hash
    	BigInteger hashMod = message.mod(hash);
    	
    	//Receives the public key from rsa
		BigInteger pubKey = rsa.getDecPubKey(hashMod);
		
		//Intializes the pair then returns the pair
		Pair <BigInteger, BigInteger> pair = new Pair<BigInteger, BigInteger>(message, pubKey);
		
		return pair;
	}

	/** 
	 * compares message, that is received from rsa
	 *		And the hash mod
	 * @param a pair of BigInteger
	 * @return a boolean to see if they message and hash mod are equal to each other
	 */
	@Override
	public boolean compare(Pair <BigInteger, BigInteger> pair) {
			
		BigInteger hashMod = pair.getKey();
	
		BigInteger message = pair.getValue();
		
    	//Receives the public key from rsa
		BigInteger msg = rsa.getDecPriKey(message);
		
		//Hashing the decrypted message
		BigInteger hashPubKey = hashMod.mod(hash);
		
		return hashPubKey.equals(msg);
	}
}