package Cryptography;



/**
*
*The interface for BlockCipher
*
* BlockCipher takes a binary sequence from a message
* then converts it using the hashmap for encrypt and decrypt
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
import java.math.BigInteger;
import java.util.Map;

/**
 * This defines the interface for Block Cipher that
 * encrypts and decrypts messages by using a 
 * Block Cipher  
 */
public interface BlockCipherADT
{
	public BigInteger encrypt(BigInteger messageBigInt);
	public BigInteger decrypt(BigInteger cipherBigInt); 

		
}
