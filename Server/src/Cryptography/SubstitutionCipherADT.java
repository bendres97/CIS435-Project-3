package Cryptography;


/**
 * 
 * Interface for SubsitutionCipher
*Uses SubsitutionCipher to change the message
*based off of a certain map
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018

*/
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Map;

public interface SubstitutionCipherADT {
	/**
	 * Calls the encryption map Uses the string builder to help make a substring
	 * and utilize the encryption map to get the desired values
	 * 
	 * @param msg
	 *            The plaintext
	 * @returns Biginteger which is an encrypted message
	 *
	 */
	public BigInteger encrypt(BigInteger msg);

	/**
	 * Calls the decryption map Uses the string builder to help make a substring
	 * and utilize the decryption map to get the desired values
	 * 
	 * 
	 * @param cipher
	 *            The encrypted value
	 * @returns Biginteger which is an plaintext message
	 */
	public BigInteger decrypt(BigInteger cipher);

}
