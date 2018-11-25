package Cryptography;

/**
*
*Interface for PolyalphabeticCipher
* Uses PolyalphabeticCipher shift a message using shift values
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
import java.math.BigInteger;
import java.util.List;

/**
Interface that abstract methods to be 
performed on a PolyalphabeticCipher
@author Andrew Bradley
@version 1.00 	2018-09-18
*/
public interface PolyalphabeticCipherADT
{
	public BigInteger encrypt(BigInteger msg, BigInteger shiftValues);
	public BigInteger decrypt(BigInteger msg, BigInteger shiftValues);
}
