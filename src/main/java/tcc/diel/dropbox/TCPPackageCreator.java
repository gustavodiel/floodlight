package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class TCPPackageCreator {
    private MacAddress macSource;
    private MacAddress macDest;
    private IPv4Address ipSource;
    private IPv4Address ipDest;
    private TCP oldTCP;

    boolean useOld = true;

    public TCPPackageCreator(MacAddress macSource, MacAddress macDest, IPv4Address ipSource, IPv4Address ipDest, TCP oldTCP) {
        this.macSource = macSource;
        this.macDest = macDest;
        this.ipSource = ipSource;
        this.ipDest = ipDest;
        this.oldTCP = oldTCP;
    }


    void sendTCPPacket(IOFSwitch iofSwitch, IPv4 iPv4, Data data) {
        if (useOld) {
        // First, we create a Eth header
        Ethernet l2 = new Ethernet();
        l2.setSourceMACAddress(this.getMacSource());
        l2.setDestinationMACAddress(this.getMacDest());
        l2.setEtherType(EthType.IPv4);

        iPv4.setSourceAddress(this.getIpSource());
        iPv4.setDestinationAddress(this.getIpDest());

        oldTCP.resetChecksum();

        l2.setPayload(iPv4);

        byte[] serializedData = l2.serialize();

        OFPacketOut po = iofSwitch.getOFFactory().buildPacketOut()
                .setData(serializedData)
                .setActions(Collections.singletonList((OFAction) iofSwitch.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                .setInPort(OFPort.CONTROLLER)
                .build();

        iofSwitch.write(po);
        } else {

            MacAddress srcMac = this.getMacSource();
            MacAddress dstMac = this.getMacDest();

            OFFlowModCommand command = OFFlowModCommand.ADD;
            Match.Builder mb = iofSwitch.getOFFactory().buildMatch();
            mb.setExact(MatchField.IN_PORT, iofSwitch.getPort(OFPort.of(iofSwitch.getPorts().size())).getPortNo());

            List<OFAction> al = new ArrayList<>();
            al.add(iofSwitch.getOFFactory().actions().buildOutput().setPort(OFPort.ALL).build());

            al.add(iofSwitch.getOFFactory().actions().buildSetDlDst().setDlAddr(this.getMacDest()).build());
            al.add(iofSwitch.getOFFactory().actions().buildSetDlSrc().setDlAddr(this.getMacSource()).build());

            al.add(iofSwitch.getOFFactory().actions().buildSetNwSrc().setNwAddr(this.getIpDest()).build());
            al.add(iofSwitch.getOFFactory().actions().buildSetNwDst().setNwAddr(this.getIpSource()).build());

            DropboxFlowRuleBuilder.writeFlowMod(iofSwitch, command, mb.build(), OFPort.FLOOD, al);
        }

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
