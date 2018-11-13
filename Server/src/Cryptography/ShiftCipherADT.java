package Cryptography;


import java.math.BigInteger;


/**
 * This defines the interface for shiftCiper that
 * encrypts and decrypts a given BigInteger using a shared key
 * @author yunwang
 * @date Unknown
 */
public interface ShiftCipherADT {
    
    /**
     * Encrypt a BigInteger "msg" with a given key "shift".
     * For example, 
     * Suppose "msg = 10" and "shift = 5";
     * Encrypt(10, 5) return "15"
     *
     * @param msg  the message
     * @param shift the shift encryption key
     * @return encrypted message
     * 
     */


    public BigInteger Encrypt(BigInteger msg, BigInteger shift);
    
     /**
     * Decrypt a BigInteger "cipher" with a given key "shift".
     * For example, 
     * Suppose "cipher = 15" and "shift = 5";
     * Decrypt(15, 5) return "10"
     *
     * @param cipher  the encrypted msg
     * @param shift the shift encryption key
     * @return encrypted message
     * 
     */

    public BigInteger Decrypt(BigInteger cipher, BigInteger shift);
    
}
