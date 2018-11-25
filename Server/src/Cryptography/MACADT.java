package Cryptography;


import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
* This is the interface for MAC
* Uses MAC to check the integrity of a message
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
public interface MACADT
{
	
	//Concatonates the secret to the front of the message and hashes it,concatonates the hash to the end of the orginal message 
	public BigInteger mACEncrypt(BigInteger message, BigInteger secret);
	
	//Takes the hashCode off the top of the message, and checks that the message with the secret is equal to the attached hash 
	public boolean mACChecker(BigInteger message, BigInteger secret);

}
	
	
