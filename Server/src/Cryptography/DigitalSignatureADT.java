package Cryptography;


/**
*
*The interface for Digital Signature
*
* Checks the digital signature of a the user who was sending the message
* It was to ensure authentication 
* 
* Solves CIS435+535 Project #1 Cryptography
*
* @author Andrew Bradley
* 		
* @version 1.01 09-30-2018
*/
import java.math.BigInteger;

import javafx.util.Pair;

/**
Interface that abstract methods to be 
performed on a Digital Signature
@author Andrew Bradley
@version 1.00 	2018-09-18
*/
public interface DigitalSignatureADT
{
	public Pair<BigInteger, BigInteger> encryptMessageDigest(BigInteger message);	
	public boolean compare(Pair <BigInteger, BigInteger> pair); 
}
