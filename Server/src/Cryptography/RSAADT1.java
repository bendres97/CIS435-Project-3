package Cryptography;

/**
 * 
 * Interface for RSA
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
import java.math.BigInteger;


/**
Interface that abstract methods to be 
performed on an RSA
@author Andrew Bradley
@version 1.00 	2018-09-18
*/
public interface RSAADT1
{
	public BigInteger Encrypt(BigInteger message);
	
	public BigInteger Decrypt(BigInteger encryptedMessage);
}
