package Cryptography;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.lang.StringBuilder;

/**
 * Uses SubsitutionCipher to change the message based off of a certain map
 * 
 * Solves CIS435+535 Project #1 Cryptography
 *
 * @author Andrew Bradley
 * 
 * @version 1.01 09-30-2018
 * 
 */
public class SubsitutionCipher implements SubstitutionCipherADT {
	AsciiConverter asciiConverter = new AsciiConverter();

	/**
	 * Calls the encryption map Uses the string builder to help make a substring
	 * and utilize the encryption map to get the desired values
	 * 
	 * @param msg
	 *            The plaintext
	 * @returns Biginteger which is an encrypted message
	 *
	 */
	public BigInteger encrypt(BigInteger msg) {

		AsciiConverter asciiConverter = new AsciiConverter();

		String message = asciiConverter.BigIntToString(msg);

		// Creates the hashmap
		Map<Character, Character> myMap = new HashMap<Character, Character>();
		encryptionMapping(myMap);

		// creates Stringbuilder
		StringBuilder newString = new StringBuilder();

		for (int i = 0; i < message.length(); i++) {
			// places the value from the encryptionmapping
			// into the stringbuilder
			newString.append(myMap.get(message.charAt(i)));
		}

		String encmsg = newString.toString();
		BigInteger BigInt = asciiConverter.StringtoBigInt(encmsg);
		return BigInt;
	}

	/**
	 * Calls the decryption map Uses the string builder to help make a substring
	 * and utilize the decryption map to get the desired values
	 * 
	 * 
	 * @param cipher
	 *            The encrypted value
	 * @returns Biginteger which is an plaintext message
	 *
	 */
	public BigInteger decrypt(BigInteger cipher) {
		AsciiConverter asciiConverter = new AsciiConverter();

		String message = asciiConverter.BigIntToString(cipher);

		// Creates the hashmap
		Map<Character, Character> myMap = new HashMap<Character, Character>();
		decryptionMapping(myMap);

		// creates Stringbuilder
		StringBuilder newString = new StringBuilder();

		for (int i = 0; i < message.length(); i++) {
			// places the value from the encryptionmapping
			// into the stringbuilder
			newString.append(myMap.get(message.charAt(i)));
		}

		String encmsg = newString.toString();

		BigInteger BigInt = asciiConverter.StringtoBigInt(encmsg);
		return BigInt;
	}

	/**
	 * The first value in the .put helps the code look for a a specific value.
	 * Then the second value replaces the first value
	 * 
	 * 
	 * map.put(first value, second value)
	 * 
	 * these are being represented as chars
	 * 
	 * @param map
	 *            with two char characters
	 * @return nothing cause it's a void :)
	 */
	private void encryptionMapping(Map<Character, Character> map) {
		//
		// lower case letters
		//
		map.put('a', 'm');
		map.put('b', 'n');
		map.put('c', 'b');
		map.put('d', 'v');
		map.put('e', 'c');
		map.put('f', 'x');
		map.put('g', 'z');
		map.put('h', 'a');
		map.put('i', 's');
		map.put('j', 'd');
		map.put('k', 'f');
		map.put('l', 'g');
		map.put('m', 'h');
		map.put('n', 'j');
		map.put('o', 'k');
		map.put('p', 'l');
		map.put('q', 'p');
		map.put('r', 'o');
		map.put('s', 'i');
		map.put('t', 'u');
		map.put('u', 'y');
		map.put('v', 'y');
		map.put('w', 'r');
		map.put('x', 'e');
		map.put('y', 'w');
		map.put('z', 'q');

		//
		// special characters case letters
		//
		map.put(' ', '-');
		map.put('?', '!');
		map.put('.', ';');
		map.put(',', '/');

		//
		// upper case letters
		//
		map.put('A', 'M');
		map.put('B', 'N');
		map.put('C', 'B');
		map.put('D', 'V');
		map.put('E', 'C');
		map.put('F', 'X');
		map.put('G', 'Z');
		map.put('H', 'A');
		map.put('I', 'S');
		map.put('J', 'D');
		map.put('K', 'F');
		map.put('L', 'G');
		map.put('M', 'H');
		map.put('N', 'J');
		map.put('O', 'K');
		map.put('P', 'L');
		map.put('Q', 'P');
		map.put('R', 'O');
		map.put('S', 'I');
		map.put('T', 'U');
		map.put('U', 'Y');
		map.put('V', 'T');
		map.put('W', 'R');
		map.put('X', 'E');
		map.put('Y', 'T');
		map.put('Z', 'Q');
	}

	/**
	 * The first value in the .put helps the code look for a a specific value.
	 * Then the second value replaces the first value
	 * 
	 * DecryptionMapping is the inverse of EncryptionMapping map.put(first
	 * value, second value)
	 * 
	 * these are being represented as chars
	 * 
	 * @param map
	 *            with two char characters
	 * @return nothing cause it's a void :)
	 */
	private void decryptionMapping(Map<Character, Character> map) {
		//
		// lower case letters
		//
		map.put('m', 'a');
		map.put('n', 'b');
		map.put('b', 'c');
		map.put('v', 'd');
		map.put('c', 'e');
		map.put('x', 'f');
		map.put('z', 'g');
		map.put('a', 'h');
		map.put('s', 'i');
		map.put('d', 'j');
		map.put('f', 'k');
		map.put('g', 'l');
		map.put('h', 'm');
		map.put('j', 'n');
		map.put('k', 'o');
		map.put('l', 'p');
		map.put('p', 'q');
		map.put('o', 'r');
		map.put('i', 's');
		map.put('u', 't');
		map.put('y', 'u');
		map.put('t', 'v');
		map.put('r', 'w');
		map.put('e', 'x');
		map.put('w', 'y');
		map.put('q', 'z');

		//
		// special characters case letters
		//
		map.put('-', ' ');
		map.put('!', '?');
		map.put(';', '.');
		map.put('/', ',');

		//
		// upper case letters
		//
		map.put('M', 'A');
		map.put('N', 'B');
		map.put('B', 'C');
		map.put('V', 'D');
		map.put('C', 'E');
		map.put('X', 'F');
		map.put('Z', 'G');
		map.put('A', 'H');
		map.put('S', 'I');
		map.put('D', 'J');
		map.put('F', 'K');
		map.put('G', 'L');
		map.put('H', 'M');
		map.put('J', 'N');
		map.put('K', 'O');
		map.put('L', 'P');
		map.put('P', 'Q');
		map.put('O', 'R');
		map.put('I', 'S');
		map.put('U', 'T');
		map.put('Y', 'U');
		map.put('T', 'V');
		map.put('R', 'W');
		map.put('E', 'X');
		map.put('W', 'Y');
		map.put('Q', 'Z');
	}
}
