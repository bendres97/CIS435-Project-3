package Cryptography;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.lang.StringBuilder;

/**
*
*
* CipherBlockChaining takes a binary sequence from a message
* then converts it using the hashmap for encrypt and decrypt with the help of XOR
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
public class CipherBlockChaining implements CipherBlockChainingADT {

	/**
	 *
	 * @param msg
	 * 			A message that is converted from BigInteger to String to Binary
	 * 
	 *@param IV
	 *			The IV is a set parameter that is created in the testerm
	 *			
	 *Encryption will follow the CBC algorithm
	 *	It will take 2 binary strings that are size three 
	 *		then XOR the binary strings
	 *			Then replace the binary string gathered from XOR
	 *				and exchange it with the binary from the map
	 *  
	 *@returns BigInteger that is converted from bigInteger to binary
	 * 
	 */
	@Override
	public BigInteger encrypt(BigInteger msg, BigInteger IV) {
		AsciiConverter asciiConverter = new AsciiConverter();
		String message = stringToBin(asciiConverter.BigIntToString(msg));
                
		//Creates the hashmap
		Map<String, String> myMap = new HashMap<String, String>();
		encryptionMapping(myMap);
		StringBuilder newString = new StringBuilder();
		String createmessage = "";
		String XORdecider = "";
		String cbcDecrypt = "";

		//Places the iv in front of an empty string
		cbcDecrypt = IV.toString();
		for (int i = 0; i < message.length(); i = i + 3) {
			
			createmessage = message.substring(i, i + 3);
			
			//Uses the XOR method
			XORdecider = XOR(createmessage, cbcDecrypt);
			//appends the map using XOR
			newString.append(myMap.get(XORdecider));
			createmessage = XORdecider;

			cbcDecrypt = newString.toString();
		}

		cbcDecrypt = IV.toString() + cbcDecrypt;
                
               BigInteger bigInt = new BigInteger(cbcDecrypt,2);
                             

               return bigInt;
	}

	/** 
	 * The decrypt method decrypts the message it receives
	 * 
	 * 
	 *@param encrytedmessage
	 *	A BigInteger message that was encrypted from the encrypted class 
	 * 
	 *Decryption will follow the CBC algorithm
	 *	It will take 2 binary strings that are size three 
	 *		exchanges one of the binary strings from the ash table
	 *			then XOR the binary strings
	 *				Then replace the binary string gathered from XOR
	 * @returns a BigInteger that is converted from a word to bigInteger
	 * 
	 */
	@Override
	public BigInteger decrypt(BigInteger encryptedMessage) {
		AsciiConverter asciiConverter = new AsciiConverter();
		String createmessage = "";
		String cbcEncrypt = "";
		String thisBinary = encryptedMessage.toString(2);
		System.out.println(thisBinary);
		// Takes the IV to start off the XOR function
		String XORdecider = thisBinary.substring(0, 3);

		//Creates the map
		Map<String, String> myMap = new HashMap<String, String>();

		// Inverse of the map
		decryptionMapping(myMap);

		//Starts at position three because it receives the code receives
		//the IV earlier on
		for (int i = 3; i < thisBinary.length(); i = i + 3) {
			
			createmessage = thisBinary.substring(i, i + 3);
			
			//Gets the mapped variable and gets a string from it
			String mapped = myMap.get(createmessage);
			
			//Uses the XOR function
			String XOR = XOR(mapped, XORdecider);
			cbcEncrypt += XOR;
			XORdecider = createmessage;
		}
		String conc = cbcEncrypt;

		//Converting into Binary to String
		String strBin = binToString(conc);

		BigInteger bigInt = asciiConverter.StringtoBigInt(strBin);

		return bigInt;
	}

	
	/**
	 * 
	 * Performs the XOR function on two strings
	 * @param str
	 * @param message
	 * @returns a string that was created using string builder
	 * 
	 * retrieved the idea for the code from:
	 * https://stackoverflow.com/questions/5126616/xor-operation-with-two-strings-in-java
	 */
	private String XOR(String str, String message) {
		StringBuilder newString = new StringBuilder();
		
		for (int i = 0; i < str.length(); i++) {
			newString.append((str.charAt(i) ^ message.charAt(i + (Math.abs(str.length() - message.length())))));
		}
		return newString.toString();

	}

	/**
	 * @param message
	 * @return a binary that allows us to convert a binary number to a string
	 * 
	 *         received the idea for the chunk of code from:
	 *         https://www.reddit.com/r/learnjava/comments/88rbzh/convert_binary_to_string_in_java/
	 */
	private String stringToBin(String message) {
		byte[] bytes = message.getBytes();
		StringBuilder binary = new StringBuilder();
		// adds the binary values into binary variable
		for (byte b : bytes) {
			int val = b;
			for (int i = 0; i < 8; i++) {
				binary.append((val & 128) == 0 ? 0 : 1);
				val <<= 1;
			}
		}
		String thisBinary = binary.toString();

		int intBinary = thisBinary.length() % 3;
		// adds 0 to the beginning of binary
		// so it is divisible by 3
		for (int i = 0; i < (3 - intBinary); i++) {
			thisBinary = "0" + thisBinary;
		}
		return thisBinary;
	}

	/**
	 * @param decMsg
	 * @return a string allows us to convert a string from a binary number
	 * 
	 *         received the idea for the chunck of code from:
	 *         https://stackoverflow.com/questions/917163/convert-a-string-like-testing123-to-binary-in-java
	 */
	private String binToString(String decMsg) {
		int intBinary = decMsg.length() % 8;
		// adds 0 to the beginning of binary
		// so it is divisible by 8
		for (int i = 0; i < (8 - intBinary); i++) {
			decMsg = "0" + decMsg;
		}

		// Helps the conversion from Binary to String
		StringBuilder binary = new StringBuilder();
		for (int i = 0; i < decMsg.length(); i += 8) {
			String sub = decMsg.substring(i, i + 8);
			// appends the string builder
			// parses the substring and 2
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
