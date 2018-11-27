package Cryptography;

/**
 * A User holds a name, ID, and RSA object. A User can be used as either a
 * sender or receiver.
 *
 * @author Bryan Endres ID: 8
 * @date 9-30-2018
 */
public class User implements UserADT
{

    private final RSA rsa;
    private final String name;
    private final int id;
    private static int id_counter = 0;

    /**
     * Default constructor for a user. Instantiates it's RSA keys and generates
     * a name. ID is assigned using static counter.
     */
    public User()
    {
        rsa = new RSA();
        name = "Nameless";
        id = id_counter++;
    }

    /**
     * Overload constructor for a user. Instantiates it's RSA keys and assigns
     * the given name. ID is assigned using static counter.
     *
     * @param name The name of the user
     */
    public User(String name)
    {
        rsa = new RSA();
        this.name = name;
        id = id_counter++;
    }

    @Override
    public RSAKey getPublicKey()
    {
        return rsa.getPublicKey();
    }

    @Override
    public int getID()
    {
        return id;
    }

    @Override
    public String getName()
    {
        return name;
    }
}
