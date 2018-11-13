package Cryptography;


import java.math.BigInteger;

/**
 * RSAKey holds the n and exponent values for an RSA key. Exponent is either e
 * or d depending on whether this is a public or private key, respectively.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class RSAKey implements RSAKeyADT
{

    private final BigInteger N;
    private final BigInteger EXP;

    /**
     * RSAKey can only be created by passing an n and exponent value
     *
     * @param n The n value
     * @param exp e/d for public/private key.
     */
    public RSAKey(BigInteger n, BigInteger exp)
    {
        N = n;
        EXP = exp;
    }

    @Override
    public BigInteger getN()
    {
        return N;
    }

    @Override
    public BigInteger getEXP()
    {
        return EXP;
    }

    @Override
    public boolean equals(RSAKey that)
    {
        return this.N.equals(that.getN()) && this.EXP.equals(that.getEXP());
    }

    @Override
    public String toString()
    {
        return N.toString() + ", " + EXP.toString();
    }
    
    public BigInteger crypt(BigInteger message)
    {
        return message.modPow(EXP, N);
    }
}
