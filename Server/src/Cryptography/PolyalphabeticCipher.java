package Cryptography;


import java.math.BigInteger;
import java.util.List;

/**
* Uses PolyalphabeticCipher shift a message using shift values
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
public class PolyalphabeticCipher implements PolyalphabeticCipherADT {
	
	private final int MOD_FINALE;
	private AsciiConverter asciiConverter;
	public PolyalphabeticCipher()
	{
		MOD_FINALE = 128;
		asciiConverter = new AsciiConverter();
	}
	
	/**
	 * Shifts the value by taking the message at a point then adding the shift
	 * @param msg
	 * 		the message gets shifted using shiftValues
	 * @param shiftValues
	 * 		A variable created by the tester
	 * 
	 * @return a bigInteger that is a message sifted by the shiftValues that repeat to create a loop
	 */
	@Override
	public BigInteger encrypt(BigInteger msg, BigInteger shiftValues) {
		String message = asciiConverter.BigIntToString(msg);
		
		String shift = asciiConverter.BigIntToString(shiftValues);
		
		String shifting = "";
    	
		for(int i= 0; i<message.length(); i++)
		{
			//Add the two values of the message at char point i
			//and the shift value at i 
			//then mod result
			shifting += (char)((message.charAt(i) +shift.charAt(i%shift.length()))%MOD_FINALE);	
		}
		
		//Converts back to BigInteger
		BigInteger bigInt = asciiConverter.StringtoBigInt(shifting);
		
		return bigInt;		
	}

	/**
	 * 	
	 * Shifts the value by taking the message at a point then subtracting the shift
	 *  @param BigInteger msg 
	 *  	shifted back using the shift values
	 *  @param BigInteger shiftValues
	 *  	Words that is created in the tester
	 *  
	 *  @return BigInteger
	 *  	Returns the original message
	 */
	@Override
	public BigInteger decrypt(BigInteger msg, BigInteger shiftValues) {
		String message = asciiConverter.BigIntToString(msg);
		String shift = asciiConverter.BigIntToString(shiftValues);
		String shifting = "";
		for(int i= 0; i<message.length(); i++)
		{
			//Add the two values of the message at char point i
			//and the shift value at i 
			//then mod result
			int value = (message.charAt(i) -shift.charAt(i%shift.length())%MOD_FINALE);
			//adds 128 if value is less than 0
			if(value<0)
			{
				value+=MOD_FINALE;
			}
			shifting += (char)value;
		}
		
		BigInteger bigInt = asciiConverter.StringtoBigInt(shifting);
		
		return bigInt;
	}

}
