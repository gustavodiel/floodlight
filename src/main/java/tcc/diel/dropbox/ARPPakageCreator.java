package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import java.util.Collections;

class ARPPakageCreator {
    private MacAddress senderMac;
    private MacAddress targetMac;
    private MacAddress destinationMac;
    private IPv4Address senderIp;
    private IPv4Address targetIp;

    ARPPakageCreator(MacAddress senderMac, MacAddress targetMac, MacAddress destinationMac, IPv4Address senderIp, IPv4Address targetIp) {
        this.senderMac = senderMac;
        this.targetMac = targetMac;
        this.destinationMac = destinationMac;
        this.senderIp = senderIp;
        this.targetIp = targetIp;
    }

    void sendARPPacket(IOFSwitch iofSwitch) {
        // First, we create a Eth header
        Ethernet l2 = new Ethernet();
        l2.setSourceMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"));
        l2.setDestinationMACAddress(this.destinationMac);
        l2.setEtherType(EthType.ARP);


        // Set as ARP
        ARP arp = new ARP()
                .setHardwareType(ARP.HW_TYPE_ETHERNET)
                .setProtocolType(ARP.PROTO_TYPE_IP)
                .setHardwareAddressLength((byte) 6)
                .setProtocolAddressLength((byte) 4)
                .setSenderHardwareAddress(this.senderMac)
                .setSenderProtocolAddress(this.senderIp)
                .setOpCode(ARP.OP_REPLY)
                .setTargetHardwareAddress(this.targetMac)
                .setTargetProtocolAddress(this.targetIp);


        // Set the payloads
        l2.setPayload(arp);

        // Serialize
        byte[] serializedData = l2.serialize();

        OFPacketOut po = iofSwitch.getOFFactory().buildPacketOut()
                .setData(serializedData)
                .setActions(Collections.singletonList((OFAction) iofSwitch.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                .setInPort(OFPort.CONTROLLER)
                .build();

        iofSwitch.write(po);
    }
}
