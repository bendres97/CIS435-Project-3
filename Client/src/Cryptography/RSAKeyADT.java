package Cryptography;


import java.math.BigInteger;

/**
 * The ADT for RSAKey
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
interface RSAKeyADT
{

    /**
     * Returns the n variable from the RSAKey
     *
     * @return n
     */
    public BigInteger getN();

    /**
     * Returns the exponent from the RSAKey (either e or d)
     *
     * @return Exponent value
     */
    public BigInteger getEXP();

    /**
     * Checks to see if this RSAKey is equal to the given RSAKey
     *
     * @param that RSAKey to compare to this RSAKey
     * @return True if the keys are equal
     */
    public boolean equals(RSAKey that);

    /**
     * Provides a String representation of this RSAKey in n,d format.
     *
     * @return String representation of this RSAKey
     */
    public String toString();
}
