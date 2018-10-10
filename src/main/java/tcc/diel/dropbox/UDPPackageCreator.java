package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.*;

import java.util.Collections;

class UDPPackageCreator {
    private MacAddress macSource;
    private MacAddress macDest;
    private IPv4Address ipSource;
    private IPv4Address ipDest;
    private int portSource;
    private int portDest;

    UDPPackageCreator(MacAddress macSource, MacAddress macDest, IPv4Address ipSource, IPv4Address ipDest, int portSource, int portDest) {
        this.setMacSource(macSource);
        this.setMacDest(macDest);
        this.setIpSource(ipSource);
        this.setIpDest(ipDest);
        this.setPortSource(portSource);
        this.setPortDest(portDest);
    }

    void sendUDPPacket(IOFSwitch iofSwitch, Ethernet ethernet) {
        // First, we create a Eth header
//        Ethernet l2 = new Ethernet();
//        l2.setSourceMACAddress(this.getMacSource());
//        l2.setDestinationMACAddress(this.getMacDest());
//        l2.setEtherType(EthType.IPv4);
//
//        // Then, the Payload
//        IPv4 l3 = new IPv4();
//        l3.setSourceAddress(this.getIpSource());
//        l3.setDestinationAddress(this.getIpDest());
//        l3.setTtl((byte) 64);
//        l3.setProtocol(IpProtocol.UDP);
//        l3.setFlags(IPv4.IPV4_FLAGS_DONTFRAG);
//
//
//        // Set as UDP
//        UDP l4 = new UDP();
//        l4.setSourcePort(TransportPort.of(this.getPortSource()));
//        l4.setDestinationPort(TransportPort.of(this.getPortDest()));
//
//
//        // Set the payloads
//        l2.setPayload(l3);
//        l3.setPayload(l4);
//        l4.setPayload(data);

        // Serialize
        byte[] serializedData = ethernet.serialize();

        OFPacketOut po = iofSwitch.getOFFactory().buildPacketOut()
                .setData(serializedData)
                .setActions(Collections.singletonList((OFAction) iofSwitch.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                .setInPort(OFPort.LOCAL)
                .build();

        iofSwitch.write(po);
    }

    public MacAddress getMacSource() {
        return macSource;
    }

    public void setMacSource(MacAddress macSource) {
        this.macSource = macSource;
    }

    public MacAddress getMacDest() {
        return macDest;
    }

    public void setMacDest(MacAddress macDest) {
        this.macDest = macDest;
    }

    public IPv4Address getIpSource() {
        return ipSource;
    }

    public void setIpSource(IPv4Address ipSource) {
        this.ipSource = ipSource;
    }

    public IPv4Address getIpDest() {
        return ipDest;
    }

    public void setIpDest(IPv4Address ipDest) {
        this.ipDest = ipDest;
    }

    public int getPortSource() {
        return portSource;
    }

    public void setPortSource(int portSource) {
        this.portSource = portSource;
    }

    public int getPortDest() {
        return portDest;
    }

    public void setPortDest(int portDest) {
        this.portDest = portDest;
    }
}
