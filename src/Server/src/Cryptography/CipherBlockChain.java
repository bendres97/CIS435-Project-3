package Cryptography;

import java.util.HashMap;
import java.util.Map;

/**
 * Cipher Block Chain holds encryption and decryption maps and methods for
 * encrypting and decrypting given messages.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class CipherBlockChain implements CipherBlockChainADT
{

    private final Map<String, String> ENCRYPTION_MAP;
    private final Map<String, String> DECRYPTION_MAP;

    public CipherBlockChain()
    {
        //Instantiate maps
        ENCRYPTION_MAP = new HashMap();
        DECRYPTION_MAP = new HashMap();

        //Create a mapping
        ENCRYPTION_MAP.put("000", "011");
        ENCRYPTION_MAP.put("001", "101");
        ENCRYPTION_MAP.put("010", "001");
        ENCRYPTION_MAP.put("011", "100");
        ENCRYPTION_MAP.put("100", "110");
        ENCRYPTION_MAP.put("101", "111");
        ENCRYPTION_MAP.put("110", "010");
        ENCRYPTION_MAP.put("111", "000");

        //Create an inverse map for decryption
        for (String string : ENCRYPTION_MAP.keySet())
        {
            //Take the values from encryption map and make them keys in decryption
            DECRYPTION_MAP.put(ENCRYPTION_MAP.get(string), string);
        }
    }

    @Override
    public String Encrypt(String input, String IV)
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

        //Parse ciphertext by XORing values using the encryption map
        String ciphertext = "";
        for (int index = 0; index < binary.length(); index += 3)
        {
            String xorMap = ENCRYPTION_MAP.get(XOR(binary.substring(index, index + 3), IV));
            ciphertext += xorMap;

            //Set IV to the result of the XOR operation.
            IV = xorMap;
        }

        return ciphertext;
    }

    @Override
    public String Decrypt(String input, String IV)
    {
        //Parse decryption by XORing values with decryption map
        String decryption = "";
        for (int index = 0; index < input.length(); index += 3)
        {
            String parse = input.substring(index, index + 3);
            String mapped = DECRYPTION_MAP.get(parse);
            String xor = XOR(mapped, IV);
            decryption += xor;

            //Set IV to the parse
            IV = parse;
        }

        //Convert from binary back to string
        //Start by ensuring length is divisible by 8.
        int mod = decryption.length() % 8;
        if (mod != 0)
        {
            //Add calculated amount of 0s to front of binary string
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

    /**
     * XORs two binary string values together.
     *
     * @param a First string to XOR
     * @param b Second string to XOR
     * @return The resulting string of XOR operation
     */
    private String XOR(String a, String b)
    {
        //Equal length check
        if (a.length() != b.length())
        {
            System.out.println("STRINGS NOT EQUAL (XOR)");
            return "STRINGS NOT EQUAL";
        }

        //Parse XOR string
        String xor = "";
        for (int index = 0; index < a.length(); index++)
        {
            if (a.charAt(index) == b.charAt(index))
            {
                xor += "0";
            }
            else
            {
                xor += "1";
            }
        }

        return xor;
    }
}
