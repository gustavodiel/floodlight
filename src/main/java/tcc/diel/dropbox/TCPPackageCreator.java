package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.*;

import java.util.Collections;

class TCPPackageCreator {
    private MacAddress macSource;
    private MacAddress macDest;
    private IPv4Address ipSource;
    private IPv4Address ipDest;
    private TCP oldTCP;

    TCPPackageCreator(MacAddress macSource, MacAddress macDest, IPv4Address ipSource, IPv4Address ipDest, TCP old) {
        this.setMacSource(macSource);
        this.setMacDest(macDest);
        this.setIpSource(ipSource);
        this.setIpDest(ipDest);
        this.oldTCP = old;
    }

    void sendTCPPacket(IOFSwitch iofSwitch, Data data) {
        // First, we create a Eth header
        Ethernet l2 = new Ethernet();
        l2.setSourceMACAddress(this.getMacSource());
        l2.setDestinationMACAddress(this.getMacDest());
        l2.setEtherType(EthType.IPv4);

        // Then, the Payload
        IPv4 l3 = new IPv4();
        l3.setSourceAddress(this.getIpSource());
        l3.setDestinationAddress(this.getIpDest());
        l3.setTtl((byte) 64);
        l3.setProtocol(IpProtocol.UDP);


        // Set as UDP
        oldTCP.resetChecksum();


        // Set the payloads
        l2.setPayload(l3);
        l3.setPayload(oldTCP);

        // Serialize
        byte[] serializedData = l2.serialize();

        OFPacketOut po = iofSwitch.getOFFactory().buildPacketOut()
                .setData(serializedData)
                .setActions(Collections.singletonList((OFAction) iofSwitch.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                .setInPort(OFPort.CONTROLLER)
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

}
