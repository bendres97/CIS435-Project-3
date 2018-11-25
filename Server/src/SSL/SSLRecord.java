/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SSL;

import Cryptography.MAC;
import java.math.BigInteger;

/**
 *
 * @author apbra
 */
public class SSLRecord {
    private BigInteger hd_Length;
    private BigInteger hd_Type;
    private BigInteger message;
    private BigInteger MAC;
    private MAC mac;

    /*
    Given message and data type, this method is to calculate mac and length 
    to construct a SSLRecord and print out the constructed Record. 
    */
    public SSLRecord(BigInteger type, BigInteger mess) 
    {
        hd_Length = BigInteger.valueOf(0); //I have zer0 clue how to calculate this
        hd_Type = type;
        message = mess;
        MAC = mac.authenticate(mess, type);
        
        System.out.println("SSL.Record.hd_Length = " + hd_Length);
        System.out.println("SSL.Record.hd_Type = " + hd_Type);
        System.out.println("SSL.Record.message = " + message);
        System.out.println("SSL.Record.mac = " + MAC);
    }
    /*
    “Given received receivedSSLRecordString, this method will 
1) split the  receivedSSLRecordString 
2) construct a SSLRecord, and 
3) print out the constructed SSLRecord. 

    */
    public SSLRecord(String receivedSSLRecordString)
    {
        String record [] = receivedSSLRecordString.split(" ");
//        for(int i =0; i<record.length; i++)
//        {
//            hd_Length = record[
//        }

            hd_Length = new BigInteger(record[0]);
            hd_Type = new BigInteger(record[1]);
            message = new BigInteger(record[2]);
            MAC = new BigInteger(record[3]);
            
            System.out.println("SSL.Record.hd_Length = " + hd_Length);
            System.out.println("SSL.Record.hd_Type = " + hd_Type);
            System.out.println("SSL.Record.message = " + message);
            System.out.println("SSL.Record.mac = " + MAC);
    }
    
    public BigInteger getHd_Length()
    {
        return hd_Length;
    }
    
    public BigInteger getHd_Type()
    {
        return hd_Type;
    }
    
    public BigInteger getMessage()
    {
        return message;
    }
    
    public BigInteger getMAC()
    {
        return MAC;
    }
    
}
        