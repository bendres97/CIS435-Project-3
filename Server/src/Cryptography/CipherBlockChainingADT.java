package Cryptography;
/**
*
*The interface for CipherBlockChaining
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
import java.math.BigInteger;
import java.util.Map;

public interface CipherBlockChainingADT
{

	public BigInteger encrypt(BigInteger msg, BigInteger IV);
	
	public BigInteger decrypt(BigInteger encryptedMessage);
	
}
