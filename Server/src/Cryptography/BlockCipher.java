package Cryptography;



import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.lang.StringBuilder;

/**
*
* BlockCipher takes a binary sequence from a message
* then converts it using the hashmap for encrypt and decrypt
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
public class BlockCipher implements BlockCipherADT {

	
	/** 
	 *  Calls the encryption map
	 *  Uses the string builder to help make a substring
	 *  and utilize the encryption map to 
	 *  get the desired values
	 *  
	 *  @param message
	 *  	message is a binary string that is a plaintext
	 *  
	 *  @return a binary string that is encrypted
	 *  	
	 */
	 @Override
	public BigInteger encrypt(BigInteger messageBigInt) {
		
		AsciiConverter asciiConverter = new AsciiConverter();
		String message = asciiConverter.BigIntToString(messageBigInt);
		
		//Converts value from String to binary
		String thisBinary = stringToBin(message);
		
		//Creates the hashmap
		Map<String, String> myMap = new HashMap<String, String>();
		encryptionMapping(myMap);

		String createMessage = "";
		StringBuilder newString = new StringBuilder();
		String encMsg = "";

		for (int i = 0; i < thisBinary.length(); i = i + 3) {
			// takes the substring of the string
			// so it'll takekevery 3
			createMessage = thisBinary.substring(i, i + 3);

			// applies the map function
			// places it into the string builder variable
			newString.append(myMap.get(createMessage));
			encMsg = newString.toString();
		}                

                BigInteger bigInt = new BigInteger(encMsg,2);
                
                return bigInt;
	}

	/* 
	 *  Calls the decryption map
	 *  Uses the string builder to help make a substring
	 *  and utilize the decryption map to 
	 *  get the desired values
	 *  
	 *   @param msg
	 *  	cipher is a binary string that is encrypted
	 *  
	 *  @return a binary string that is a plaintext
	 */
	 @Override
	public BigInteger decrypt(BigInteger cipherBigInt) {

		AsciiConverter asciiConverter = new AsciiConverter();
		//String message = asciiConverter.BigIntToString(cipherBigInt);
		
		//Converts value from String to binary
                
		String thisBinary = cipherBigInt.toString(2);
		
		//Creates the hashmap
		Map<String, String> myMap = new HashMap<String, String>();
		decryptionMapping(myMap);
		
		String createmessage = "";
		StringBuilder newString = new StringBuilder();
		String decMsg ="";
		for (int i = 0; i < thisBinary.length(); i= i+3) {

			// takes the substring of the string
			// so it'll take every 3
			createmessage = thisBinary.substring(i, i + 3);
			
			// applies the map function
			// places it into the string builder variable
			newString.append(myMap.get(createmessage));	
		}
		
		decMsg = newString.toString();
		
		//Converts binary to String
		String strbin =  binToString(decMsg);
		
		BigInteger bigInt = asciiConverter.StringtoBigInt(strbin);
		 
		return bigInt;
	}

	/**
	 * @param message
	 * @return a binary 
	 * 		that allows us to convert a binary number to a string
	 * 
	 * received the idea for the chunk of code from:
	 * https://www.reddit.com/r/learnjava/comments/88rbzh/convert_binary_to_string_in_java/
	 */
	private String stringToBin(String message)
	{
		byte[] bytes = message.getBytes();
		StringBuilder binary = new StringBuilder();
		//adds the binary values into binary variable
		for(byte b : bytes)
		{
			int val = b;
			for(int i = 0; i< 8; i++)
			{
				binary.append((val & 128) == 0 ? 0 : 1);
				val<<=1;
			}
		}
		String thisBinary = binary.toString();
		
		int intBinary = thisBinary.length()%3;
		//adds 0 to the beginning of binary
		//so it is divisible by 3
		for(int i=0; i<(3-intBinary); i++)
		 {
			 thisBinary= "0"+thisBinary;
		 }
		return thisBinary;
	}
	
	/**
	 * @param decMsg
	 * @return a string
	 * 		allows us to convert a string from a binary number
	 * 
	 * received the idea for the chunck of code from:
	 * https://stackoverflow.com/questions/917163/convert-a-string-like-testing123-to-binary-in-java
	 */
	private String binToString(String decMsg)
	{
		int intBinary = decMsg.length()%8;
		//adds 0 to the beginning of binary
		//so it is divisible by 8
		 for(int i=0; i<(8-intBinary); i++)
		 {
			 decMsg= "0"+decMsg;
		 }

		//Helps the conversion from Binary to String
		 StringBuilder binary = new StringBuilder();
		for(int i = 0; i< decMsg.length(); i+=8)
		{
			String sub = decMsg.substring(i, i+8);
			//appends the string builder 
			//parses the substring and 2
			binary.append((char) Integer.parseInt(sub, 2));
			
		}
		return binary.toString();
	}
	
	/** 
	 * The first value in the .put helps the code look for a 
	 * a specific value. Then the second value replaces the first
	 * value 
	 * 
	 * 	map.put(first value, second value)
	 * 
	 * these are being represented as Strings
	 * 
	 * @param map with two char characters
	 * @return nothing cause it's a void :)
	 */
	private void encryptionMapping(Map<String, String> map) {
		map.put("000", "110");
		map.put("001", "111");
		map.put("010", "011");
		map.put("011", "100");
		map.put("100", "101");
		map.put("101", "010");
		map.put("110", "000");
		map.put("111", "001");

	}

	/* 
	 * The first value in the .put helps the code look for a 
	 * a specific value. Then the second value replaces the first
	 * value 
	 * 
	 * decryptionMapping is the inverse of encryptionMapping
	 * map.put(first value, second value)
	 * 
	 * these are being represented as Strings
	 * 
	 * @param map with two char characters
	 * @return nothing cause it's a void :)
	 */
	private void decryptionMapping(Map<String, String> map) {
		map.put("110", "000");
		map.put("111", "001");
		map.put("011", "010");
		map.put("100", "011");
		map.put("101", "100");
		map.put("010", "101");
		map.put("000", "110");
		map.put("001", "111");
	}

}
