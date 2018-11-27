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
 * @author Andrew Bradley
 * @author Bryan Endres
 */
public class SSLRecord
{

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
        hd_Type = type; //0 to continue, 1 to close socket
        message = mess;
        MAC = mac.authenticate(mess, type);
        hd_Length = BigInteger.valueOf(type.toString().length() + mess.toString().length() + MAC.toString().length());

        System.out.println("SSL.Record.hd_Length:\t" + hd_Length);
        System.out.println("SSL.Record.hd_Type:\t" + hd_Type);
        System.out.println("SSL.Record.message:\t" + message);
        System.out.println("SSL.Record.mac:\t\t" + MAC);
    }

    /*
    “Given received receivedSSLRecordString, this method will 
1) split the  receivedSSLRecordString 
2) construct a SSLRecord, and 
3) print out the constructed SSLRecord. 

     */
    public SSLRecord(String receivedSSLRecordString)
    {
        String record[] = receivedSSLRecordString.split(" ");
//        for(int i =0; i<record.length; i++)
//        {
//            hd_Length = record[
//        }

        hd_Length = new BigInteger(record[0]);
        hd_Type = new BigInteger(record[1]);
        message = new BigInteger(record[2]);
        MAC = new BigInteger(record[3]);

        System.out.println("SSL.Record.hd_Length:\t" + hd_Length);
        System.out.println("SSL.Record.hd_Type:\t" + hd_Type);
        System.out.println("SSL.Record.message:\t" + message);
        System.out.println("SSL.Record.mac:\t\t" + MAC);
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
