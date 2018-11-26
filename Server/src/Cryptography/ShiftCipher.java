package Cryptography;


import java.math.BigInteger;

/**
 * This class encrypts a given BigInteger message using the ShiftCipher.
 *
 * @author yunwang
 * @date Unknown
 */
public class ShiftCipher
{

    /**
     * Encrypt a BigInteger "msg" with a given key "shift". For example, Suppose
     * "msg = 10" and "shift = 5"; Encrypt(10, 5) return "15"
     *
     * @param msg the message
     * @param shift the shift encryption key
     * @return encrypted message
     *
     */
    public BigInteger Encrypt(BigInteger msg, BigInteger shift)
    {

        return msg.add(shift);
    }

    /**
     * Decrypt a BigInteger "cipher" with a given key "shift". For example,
     * Suppose "cipher = 15" and "shift = 5"; Decrypt(15, 5) return "10"
     *
     * @param cipher the encrypted msg
     * @param shift the shift encryption key
     * @return encrypted message
     *
     */
    public BigInteger Decrypt(BigInteger cipher, BigInteger shift)
    {

        return cipher.subtract(shift);

    }

}
