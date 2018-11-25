package Cryptography;

import java.math.BigInteger;
import java.util.Random;

import javafx.util.Pair;

/**
* Uses RSA to create multiple public keys and private keys
* RSA encrypts and decrypts a particular message
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*This code was retrieved from:
*https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
*Dr. Wang gave us the website
*/

public class RSA1 implements RSAADT1 {

	private Random r = new Random();
	private BigInteger d;
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger z;
	private BigInteger e;
	private int bitLength = 512;

	
	/**
	 * 
	 * This is the construtor for RSA
	 * This sets up the variables so they 
	 * can be used in other methods
	 * 
	 */
	public RSA1()
	{
		p = BigInteger.probablePrime(bitLength, r);
		q = BigInteger.probablePrime(bitLength, r);
		n = p.multiply(q);
		z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = BigInteger.probablePrime(bitLength / 2, r);
		while (z.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(z) < 0) {
			e.add(BigInteger.ONE);
		}
		d = e.modInverse(z);
	}
	
	
	
	/**
	 * @param bitLength
	 * 		This changes so the CA can generate a bitlength that is two times the standard of a 
	 * a regular RSA
	 */
	public RSA1(int bitLength)
	{
		p = BigInteger.probablePrime(bitLength, r);
		q = BigInteger.probablePrime(bitLength, r);
		n = p.multiply(q);
		z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = BigInteger.probablePrime(bitLength / 2, r);
		while (z.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(z) < 0) {
			e.add(BigInteger.ONE);
		}
		d = e.modInverse(z);
	}
	/**
	 * @param e
	 * @param d
	 * @param n
	 * 
	 * This is the overloadedd constructor. this is a pointless method
	 * it was never used
	 */
	public RSA1(BigInteger e, BigInteger d, BigInteger n)
    {
        this.e = e;
        this.d = d;
        this.n = n;
    }
	/**
	 * 
	 * Encrypts the RSA
	 * Since it is encrypting, it is taking the mod pow of e and n
	 * @param BigInteger message
	 * 		Receives the message that is generating in the rsa
	 * @return encrypted message
	 * 
	 */
	public BigInteger Encrypt(BigInteger message) {

		
		return message.modPow(e, n);
		
	}

	/**
	 * 
	 * Encrypts the RSA
	 * Since it is encrypting, it is taking the mod pow of e and n
	 * @param BigInteger message
	 * 		Receives the message that is generating in the rsa
	 * @return decrypted message
	 * 
	 */
	@Override
	public BigInteger Decrypt(BigInteger encryptedMessage) {
		return encryptedMessage.modPow(d, n);
		
	}
	

	/**
	 * 
	 * Decrypts the RSA
	 * Since it is encrypting, it is taking the mod pow of e and n
	 * @param BigInteger message
	 * 		Receives the message that is generating in the rsa
	 * @return encrypted public key
	 * 
	 */
	public BigInteger getDecPubKey(BigInteger message) {
		
		//Returns the public key
		//THis is from the encrypt from RSA
		return message.modPow(e, n);

	}
	/**
	 * 
	 * Decrypts the RSA
	 * Since it is encrypting, it is taking the mod pow of d and n
	 * @param BigInteger message
	 * 		Receives the message that is generating in the rsa
	 * @return encrypted private key
	 * 
	 */
	public BigInteger getDecPriKey(BigInteger encryptedMessage) {

		//returns the private key
		//this is from the decrypt from RSA
		return encryptedMessage.modPow(d, n);
		
		
	}
	/**
	 * This class is for Digital Signature class
	 @param BigInteger message
	 * 		Receives the message that is generating in the rsa
	 * @return the e and the n so the public key can be accessed
	 */
	public Pair<BigInteger, BigInteger> getPubKey()	
	{
		Pair<BigInteger, BigInteger> getPubKey = new  Pair<BigInteger, BigInteger>(e,n);
		
		return getPubKey;
	}
	/**
	 * This class is for Digital Signature class
	 @param BigInteger message
	 * 		Receives the message that is generating in the rsa
	 * @return the e and the n so the public key can be accessed
	 */
	public Pair<BigInteger, BigInteger> getPrivKey()	
	{
		Pair<BigInteger, BigInteger> getPrivKey = new  Pair<BigInteger, BigInteger>(d,n);
		
		return getPrivKey;
	}


	
}
