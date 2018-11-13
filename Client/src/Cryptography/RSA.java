package Cryptography;


import java.math.BigInteger;
import java.util.Random;

/**
 * RSA object generates its keys at instantiation and encrypts or decrypts
 * messages. RSAKeys are computed at instantiation and stored in the RSA Object.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 *
 */
public class RSA implements RSAADT
{

    //Instance variables
    private final BigInteger N;
    private final BigInteger E;
    private final BigInteger D;
    private final int BIT_LENGTH;

    //Holds the public and private key values
    private final RSAKey PUBLIC_KEY;
    private final RSAKey PRIVATE_KEY;

    /**
     * Default Constructor. Initializes all variables. Code adapted from
     * https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
     */
    public RSA()
    {
        BIT_LENGTH = 512;
        Random r = new Random();
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, r);
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH, r);
        BigInteger z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        N = p.multiply(q);
        E = BigInteger.probablePrime(BIT_LENGTH / 2, r);
        while (z.gcd(E).compareTo(BigInteger.ONE) > 0 && E.compareTo(z) < 0)
        {
            E.add(BigInteger.ONE);
        }

        D = E.modInverse(z);

        PUBLIC_KEY = new RSAKey(N, E);
        PRIVATE_KEY = new RSAKey(N, D);
    }

    /**
     * Constructor that takes inputs. Code adapted from
     * https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
     *
     * @param e e
     * @param d d
     * @param n n
     */
    public RSA(BigInteger e, BigInteger d, BigInteger n)
    {
        BIT_LENGTH = 512;
        this.E = e;
        this.D = d;
        this.N = n;
        PUBLIC_KEY = new RSAKey(n, e);
        PRIVATE_KEY = new RSAKey(n, d);
    }

    /**
     * Constructor that takes bitLength as an argument. This is used for
     * Certificate Authority due to mathematical errors when trying to encrypt
     * keys of the same bit length. Code adapted from
     * https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
     *
     * @param bitLength The number of bits to use for this key
     */
    public RSA(int bitLength)
    {
        BIT_LENGTH = bitLength;
        Random r = new Random();
        BigInteger p = BigInteger.probablePrime(bitLength, r);
        BigInteger q = BigInteger.probablePrime(bitLength, r);
        BigInteger z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        N = p.multiply(q);
        E = BigInteger.probablePrime(bitLength / 2, r);
        while (z.gcd(E).compareTo(BigInteger.ONE) > 0 && E.compareTo(z) < 0)
        {
            E.add(BigInteger.ONE);
        }

        D = E.modInverse(z);

        PUBLIC_KEY = new RSAKey(N, E);
        PRIVATE_KEY = new RSAKey(N, D);
    }

    @Override
    public BigInteger Encrypt(BigInteger msg)
    {
        return msg.modPow(E, N);
    }

    @Override
    public BigInteger Decrypt(BigInteger cipherIn)
    {
        return cipherIn.modPow(D, N);
    }

    @Override
    public RSAKey getPublicKey()
    {
        return PUBLIC_KEY;
    }

    @Override
    public RSAKey getPrivateKey()
    {
        return PRIVATE_KEY;
    }
}
