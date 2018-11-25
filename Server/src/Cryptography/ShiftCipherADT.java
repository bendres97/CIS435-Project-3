package Cryptography;

import java.math.BigInteger;


/**
 * This defines the interface for shiftCiper that
 * encrypts and decrypts a given BigInteger using a shared key
 * @author Andrew Bradley
 */
public interface ShiftCipherADT {
    
	/**
	 * Instead of adding shift to message, the letters will shift right in
	 * accordance to the alphabet
	 * 
	 * For example, suppose Hello is in the tester, it turns into big integer by
	 * using ascii converter Encrypt will convert the BigInteger back to string
	 * and shift the string to the right in accordance to how big shift is
	 *
	 * @param msg
	 *            the message
	 * @param shift
	 *            the shift encryption key
	 * @return encrypted message
	 * 
	 */

    public BigInteger encrypt(BigInteger msg, BigInteger shift);
    
	/**
	 * Instead of adding shift to message, the letters will shift right in
	 * accordance to the alphabet
	 * 
	 * For example, suppose Hello is in the tester, it turns into big integer by
	 * using ascii converter Decrypt will convert the BigInteger back to string
	 * and shift the string to the left in accordance to how big shift is
	 *
	 * @param msg
	 *            the message
	 * @param shift
	 *            the shift encryption key
	 * @return encrypted message
	 * 
	 */

    public BigInteger decrypt(BigInteger cipher, BigInteger shift);
    
}
