package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import org.projectfloodlight.openflow.types.EthType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DropboxHelper {
    protected static final Logger log = LoggerFactory.getLogger(DropboxHelper.class);

    public static boolean shouldDropPackage(Ethernet eth, IOFSwitch sw) {
        if (eth.getPayload() instanceof IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            if (ipv4.getPayload() instanceof UDP) {
                UDP udp = (UDP) ipv4.getPayload();

                if (ipv4.getSourceAddress().toString().equals("10.0.0.1") && ipv4.getDestinationAddress().isBroadcast()) {
                    log.info("Dropped Broadcast!");
                    return true;
                }

            }
        }

        if (eth.getEtherType() == EthType.ARP) {
            ARP arp = (ARP) eth.getPayload();
            String ipTarget = arp.getTargetProtocolAddress().toString();
            String ipSender = arp.getSenderProtocolAddress().toString();
            if ((ipSender.equals("10.0.0.1") && (ipTarget.equals("10.0.2.2") || ipTarget.equals("10.0.2.3"))) ||
                    (ipSender.equals("10.0.0.2") && (ipTarget.equals("10.0.1.2")))) {
                log.info("Dropped ARP! {} {}", ipSender, ipTarget);
                return true;
            }
        }
        return false;
    }
}
