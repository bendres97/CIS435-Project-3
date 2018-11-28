package Network;

/**
 *
 * This class defines the interface for the Network Class that describes the
 * network infrastructure
 *
 * @author Andrew Bradley
 * @author Bryan Endres
 * @since 10-29-2018
 */
public interface NetworkADT
{

    /**
     *
     * @param pk pk is a packet This doesn't return anything because it is a
     * void
     *
     * Gives the packet to the sender
     */
    public void sendToReceiver(Packet pk);

    /**
     *
     * @param error An integer This doesn't return anything because it is a void
     *
     * If the error is 0, the in from sender goes to out to sender else it will
     * set error in message
     */
    public void setInternetCondition(int error);

    /**
     * @return a variable that is being called from the Packet class Returns out
     * to receiver
     */
    public Packet receiveFromSender();
}
