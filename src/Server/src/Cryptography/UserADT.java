package Cryptography;

/**
 * The ADT for a User object.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
interface UserADT
{

    /**
     * Returns the public key for a user.
     *
     * @return This user's public key.
     */
    public RSAKey getPublicKey();

    /**
     * Returns the user's ID
     *
     * @return This user's ID
     */
    public int getID();

    /**
     * Returns the user's name.
     *
     * @return This user's name
     */
    public String getName();
}
