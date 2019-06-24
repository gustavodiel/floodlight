package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.*;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

public class DropboxHelper {
    protected static final Logger log = LoggerFactory.getLogger(DropboxHelper.class);

    public static boolean shouldDropPackage(Ethernet eth, IOFSwitch sw) {
        if (eth.getPayload() instanceof IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            if (ipv4.getPayload() instanceof UDP) {
                UDP udp = (UDP) ipv4.getPayload();

                if (ipv4.getSourceAddress().toString().equals("10.0.0.1") && ipv4.getDestinationAddress().isBroadcast()) {
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
                return true;
            }
        }
        return false;
    }

    static boolean isUDPLANSync(UDP udp, IPv4 ip) {
        int srcPort = udp.getSourcePort().getPort();
        int dstPort = udp.getDestinationPort().getPort();

        if (DropboxAnalyzer.NO_ONLINE_MODE && (srcPort == DropboxAnalyzer.NO_ONLINE_PORT_NUMBER || dstPort == DropboxAnalyzer.NO_ONLINE_PORT_NUMBER))
            return true;

        return ((dstPort >= 17500 && dstPort <= 17600) || (srcPort >= 17500 && srcPort <= 17600));
    }


    static boolean isTCPLANSync(TCP tcp, IPv4 ip) {
        int srcPort = tcp.getSourcePort().getPort();
        int dstPort = tcp.getDestinationPort().getPort();

        if (DropboxAnalyzer.NO_ONLINE_MODE && (srcPort == DropboxAnalyzer.NO_ONLINE_PORT_NUMBER || dstPort == DropboxAnalyzer.NO_ONLINE_PORT_NUMBER))
            return true;

        return ((dstPort >= 17500 && dstPort <= 17600) || (srcPort >= 17500 && srcPort <= 17600));
    }

    static boolean isHostsOnSameSwitch(IDevice host1, IDevice host2){
        if (host1 == null || host2 == null) { // How could this be?
            return false;
        }

        for (SwitchPort switchPort : host1.getAttachmentPoints()) {
            DatapathId datapathId1 = switchPort.getNodeId();
            for (SwitchPort switchPort2 : host2.getAttachmentPoints()) {
                DatapathId datapathId2 = switchPort2.getNodeId();
                if (datapathId1.equals(datapathId2)) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean isBannedIp(IPv4Address ip) {
        return ip.toString().equals("10.0.0.1") || ip.toString().equals("10.0.0.2");
    }

    static IDevice findDeviceFromIP(IPv4Address ip) {
        // Fetch all known devices
        Collection<? extends IDevice> allDevices = DropboxAnalyzer.deviceManagerService.getAllDevices();

        IDevice dstDevice = null;
        for (IDevice device : allDevices) {
            for (int i = 0; i < device.getIPv4Addresses().length; ++i) {
                if (device.getIPv4Addresses()[i].equals(ip)) {
                    dstDevice = device;
                    break;
                }
            }
        }

        return dstDevice;
    }

}
