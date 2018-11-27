package Cryptography;

import java.util.HashMap;
import java.util.Map;

/**
 * Block cipher stores encryption and decryption HashMaps and provides encrypt
 * and decrypt methods for use with given messages.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class BlockCipher implements BlockCipherADT
{

    Map<String, String> encryptionMap;
    Map<String, String> decryptionMap;

    public BlockCipher()
    {
        //Instantiate maps
        encryptionMap = new HashMap();
        decryptionMap = new HashMap();

        //Create mapping
        encryptionMap.put("000", "011");
        encryptionMap.put("001", "101");
        encryptionMap.put("010", "001");
        encryptionMap.put("011", "100");
        encryptionMap.put("100", "110");
        encryptionMap.put("101", "111");
        encryptionMap.put("110", "010");
        encryptionMap.put("111", "000");

        //Create an inverse map for decryption
        for (String string : encryptionMap.keySet())
        {
            decryptionMap.put(encryptionMap.get(string), string);
        }
    }

    @Override
    public String Encrypt(String input)
    {
        //Convert the input String to binary
        //Adapted from https://stackoverflow.com/questions/917163/convert-a-string-like-testing123-to-binary-in-java
        byte[] message = input.getBytes();
        String binary = "";
        for (byte digit : message)
        {
            int value = digit;
            for (int i = 0; i < 8; i++)
            {
                binary += ((value & 128) == 0 ? 0 : 1);
                value <<= 1;
            }
        }

        //Ensure that length of binary is divisible by three for mapping.
        switch (binary.length() % 3)
        {
            case 1:
            {
                binary = "00" + binary;
                break;
            }
            case 2:
            {
                binary = "0" + binary;
                break;
            }
            default:
            {
                //Do Nothing
            }
        }

        //Parse ciphertext by mapping values using the encryption map
        String ciphertext = "";

        for (int index = 0; index < binary.length(); index += 3)
        {
            ciphertext += encryptionMap.get(binary.substring(index, index + 3));
        }

        return ciphertext;
    }

    @Override
    public String Decrypt(String output)
    {
        String decryption = "";
        //Parse decryption by mapping values with decryption map

        for (int index = 0; index < output.length(); index += 3)
        {
            decryption += decryptionMap.get(output.substring(index, index + 3));
        }

        //Convert from binary back to string
        //Start by ensuring length is divisible by 8.
        int mod = decryption.length() % 8;
        if (mod != 0)
        {
            for (int index = 0; index < 8 - mod; index++)
            {
                decryption = "0" + decryption;
            }
        }

        //Convert binary values to char values and parse to String
        //Adapted from https://www.reddit.com/r/learnjava/comments/88rbzh/convert_binary_to_string_in_java/
        String plaintext = "";
        for (int index = 0; index < decryption.length(); index += 8)
        {
            String word = decryption.substring(index, index + 8);
            char letter = (char) Integer.parseInt(word, 2);
            if ((int) letter == 0)
            {
                if (index != 0)
                {
                    plaintext += letter;
                }
            }
            else
            {
                plaintext += letter;
            }
        }

        return plaintext;
    }
}
