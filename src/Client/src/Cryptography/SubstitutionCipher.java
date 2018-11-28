package Cryptography;

/**
 * The Substitution Cipher encrypts and decrypts based on substituting values in
 * the given string for a randomly generated set of values.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class SubstitutionCipher implements SubstitutionCipherADT
{

    @Override
    public String Encrypt(String input, char[] substitutionKey)
    {
        String ciphertext = "";
        for (int index = 0; index < input.length(); index++)
        {
            int asciiNum = (int) input.charAt(index);
            ciphertext += substitutionKey[asciiNum];
        }

        return ciphertext;
    }

    @Override
    public String Decrypt(String cryptInput, char[] substitutionKey)
    {
        String plaintext = "";
        for (int index = 0; index < cryptInput.length(); index++)
        {
            char character = cryptInput.charAt(index);
            boolean found = false;
            for (int n = 0; n < substitutionKey.length && !found; n++)
            {
                if (character == substitutionKey[n])
                {
                    plaintext += (char) n;
                    found = true;
                }
            }
        }

        return plaintext;
    }

}
