package Cryptography;

import java.math.BigInteger;

/**
 * The interface of AsciiConverter to convert String message to BigInteger data
 * and visa versa.
 *
 * @author yunwang
 */
public interface AsciiConverterADT
{

    /**
     * Convert String message into BigInteger data. For example: if inStr =
     * "Hello", return result = 172201208208211. Note that, for each character,
     * the ASCII value is added by 100 to make uniform 3-digits for all
     * characters. 'H' has a ascii code of 72, and 100 is added to make 3 digits
     *
     * @param inStr String message to be converted
     * @return the BigInteger data of the inStr using (shifted) ASCII table
     *
     */
    public BigInteger StringtoBigInt(String inStr);

    /**
     * Convert BigInteger data to String message. For example: if inBigInt
     * =172201208208211, return result = "Hello" . Note that, for each
     * character, the ASCII value is added by 100 to make uniform 3-digits for
     * all characters. As a result, every digits integer is shifted back by 100
     * before converted to a character.
     *
     * @param inBigInt BigInteger data to be converted
     * @return the String message of the inBigInt using (shifted) ASCII table
     *
     */
    public String BigIntToString(BigInteger inBigInt);

}
