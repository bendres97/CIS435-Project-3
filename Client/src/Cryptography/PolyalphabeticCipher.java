package Cryptography;

/**
 * Polyalphabetic Cipher has no constructor and only encrypts/decrypts messages
 * using supplied shifts.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class PolyalphabeticCipher implements PolyalphabeticCipherADT
{

    //The maximum value for 7-bit ASCII
    private final static int ASCII_MAX = 128;

    @Override
    public String Encrypt(String msg, String shift)
    {
        //String for storing return value
        String encrypted = "";

        //Iterate through message and add value of shift
        for (int index = 0; index < msg.length(); index++)
        {
            //index % length ensures that shift repeats within boundaries. % ASCII preserves 7-bit ASCII
            encrypted += (char) ((msg.charAt(index) + shift.charAt(index % shift.length())) % ASCII_MAX);
        }

        return encrypted;
    }

    @Override
    public String Decrypt(String msg, String shift)
    {
        //String for storing return value
        String decrypted = "";

        //Iterate through message and subtract value of shift
        for (int index = 0; index < msg.length(); index++)
        {
            //Store the ascii value. index % length ensures that shift repeats within boundaries. % ASCII preserves 7-bit ASCII
            int ascii = ((msg.charAt(index) - shift.charAt(index % shift.length())) % ASCII_MAX);
            if (ascii < 0)
            {
                //Mod can return a negative value, we need to correct if this happens
                ascii += ASCII_MAX;
            }

            //Cast corrected value to a char and add to string
            decrypted += (char) ascii;
        }

        return decrypted;
    }
}
