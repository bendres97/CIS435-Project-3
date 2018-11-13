package Cryptography;


import java.math.BigInteger;

/**
 *
 * AsciiConverter is to convert String message to BigInteger data and visa
 * versa. Solves CIS435+535 Project #1 Cryptography
 *
 * @author Yun Wang
 * @version 1.01 09-07-2018
 */
public class AsciiConverter implements AsciiConverterADT
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
    public BigInteger StringtoBigInt(String inStr)
    {

        String result = "";

        for (int i = 0; i < inStr.length(); i++)
        {

            char ch = inStr.charAt(i);

            result += (ch + 100); // add 100 to make  three digits for all characters
            // System.out.println("\tch = " + ch + ", result = " + result);

        }
        //  System.out.println("\tAsciiConverter (Converted) result = " + result);

        return new BigInteger(result);

    }

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
    public String BigIntToString(BigInteger inBigInt)
    {

        String result = "";

        String inString = inBigInt.toString();

        int length = inString.length();
        int numChar = length / 3;

        // System.out.println("\tlength = " + length + ", numChar =  " + numChar);
        int index = 0;
        for (int i = 0; i < numChar; i++)
        {

            String temp = inString.substring(index, index + 3);

            int charInt = Integer.parseInt(temp);
            char ch = (char) (charInt - 100);

            // System.out.println("\ttemp = " + temp + ", charInt = " + charInt + ", ch = " + ch);
            result += ch;
            index += 3;

        }
        //   System.out.println("\tresult = " + result);
        return result;

    }

}
