package tcc.diel.dropbox;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFConnection;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.*;
import org.python.antlr.ast.Str;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Set;

/*
Pls read:
    https://floodlight.atlassian.net/wiki/spaces/floodlightcontroller/pages/9142279/How+to+Process+a+Packet-In+Message
    https://www2.cs.duke.edu/courses/fall14/compsci590.4/notes/slides_floodlight_updated.pdf
    https://github.com/floodlight/floodlight/blob/master/src/main/java/net/floodlightcontroller/topology/TopologyManager.java
    https://floodlight.atlassian.net/wiki/spaces/floodlightcontroller/pages/9142281/How+to+Create+a+Packet+Out+Message

 */

public class DropboxAnalyzer {
	
	protected static final Logger log = LoggerFactory.getLogger(DropboxAnalyzer.class);

	protected static boolean NO_ONLINE_MODE = true;
	protected static int NO_ONLINE_PORT_NUMBER = 12312;


	static HashMap<IPv4Address, MacAddress> arpTable = new HashMap<>();
	
	public DropboxAnalyzer() {
		// TODO Auto-generated constructor stub
	}
	
	public DropboxResponses isEthernetPackageLANSync(Ethernet eth) {
		
		 if (eth.getEtherType() == EthType.IPv4) {
	            /* Get the payload */
	            IPv4 ipv4 = (IPv4) eth.getPayload();

	            /* 
	             * Here we check if it's TCP or UDP
	             */
	            if (ipv4.getProtocol() == IpProtocol.TCP) {
	            	
	                TCP tcp = (TCP) ipv4.getPayload();
	  
	                int srcPort = tcp.getSourcePort().getPort();
	                int dstPort = tcp.getDestinationPort().getPort();

	                log.info("TCP SOURCE: {}:{}", ipv4.getSourceAddress(), srcPort);
	                log.info("TCP DESTINATION: {}:{}", ipv4.getDestinationAddress(), dstPort);
	                
	                if (this.isPortLANSync(dstPort, srcPort)){
	                	return DropboxResponses.LANSYNC;
	                }
	                 
	            } else if (ipv4.getProtocol() == IpProtocol.UDP) {
	            	
	                UDP udp = (UDP) ipv4.getPayload();
	  
	                int srcPort = udp.getSourcePort().getPort();
	                int dstPort = udp.getDestinationPort().getPort();

	                log.info("UDP: {} {}", srcPort, dstPort);
	                
	                if (this.isPortLANSync(dstPort, srcPort)) {
	                	return DropboxResponses.LANSYNC;
	                }
	            }
	            
	        } else if (eth.getEtherType() == EthType.ARP) {
	        	
	            ARP arp = (ARP) eth.getPayload();
	            
	            log.info("ARP: {}", arp.toString());

	            return DropboxResponses.ARP;
	        } else {
	            log.info("Nao Sei: {}", eth.getEtherType());
	        }
		
		return DropboxResponses.CONTINUE;
	}

	public void processARPRequest(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        ARP arp = (ARP) eth.getPayload();

        IPv4Address target = arp.getTargetProtocolAddress();

        log.info(target.toString());

        if (arpTable.containsKey(target)) {
            MacAddress macTarget = arpTable.get(target);
            if (macTarget == null) {
                arpTable.put(target, generateMacAddresForFakeIp(target));
            }
            macTarget = arpTable.get(target);

            ArpRequestInfo info = new ArpRequestInfo( eth.getSourceMACAddress(), eth.getDestinationMACAddress(), macTarget, IPv4Address.of("255.255.255.255"), target);

            sendARPPacket(iofSwitch, info);

        }

    }

    private MacAddress generateMacAddresForFakeIp(IPv4Address iPv4Address) {
	    String strMac = "Ba:ba:ca:";
	    String last = String.format("%06d", arpTable.size());

        last = last.substring(0, 2) + ":" + last.substring(2, 4) + ":" + last.substring(4, 6);

        return MacAddress.of(strMac + last);
    }

	public boolean shouldDropPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        log.info("Processing LANSync package!");

        IPv4 ipv4 = (IPv4) eth.getPayload();

        if (packageIsTCP(ipv4.getPayload())) {
            return processTCPPackage(eth, packetIn, iofSwitch, topologyService, floodlightProviderService, switchService, routingEngineService, linkService, deviceManagerService);
        } else {
            processUDPPackage(eth, packetIn, iofSwitch, topologyService, floodlightProviderService, switchService, routingEngineService, linkService, deviceManagerService);
            return false;
        }
	}

	private boolean packageIsTCP(IPacket data) {
	    return data instanceof TCP;
    }

	private void processUDPPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        IPv4 ipv4 = (IPv4) eth.getPayload();

        UDP udp = (UDP)ipv4.getPayload();

	    Data packageData = (Data) udp.getPayload();

        log.info(String.valueOf(udp.getSourcePort()));

        if (udp.getSourcePort().getPort() == 6695) {
            log.info("Our generated package! Staph");
            return;
        }


        for (DatapathId switchId : switchService.getAllSwitchDpids()){
            IOFSwitch toSendSwitch = switchService.getSwitch(switchId);

            if (!topologyService.isInSameCluster(toSendSwitch.getId(), iofSwitch.getId())) {

                PacketTopologyInfo info = new PacketTopologyInfo(
                        MacAddress.FULL_MASK, eth.getDestinationMACAddress(),
                        createFakeIp(ipv4.getSourceAddress()), IPv4Address.of("255.255.255.255"),
                        6695, 12312);

                sendUDPPacket(toSendSwitch, info, packageData);
            }

        }
    }

    private IPv4Address createFakeIp(IPv4Address iPv4Address) {
        arpTable.put(iPv4Address, null);

	    return iPv4Address;
    }

    private boolean isHostsOnSameSwitch(IDevice host1, IDevice host2, IOFSwitchService switchService){
	    if (host1 == null || host2 == null) { // How could this be?
            log.error("Null!");
	        return false;
        }
        log.info("Host 1:" + host1.toString());
        log.info("Host 2:" + host2.toString());

        log.info("[ SWITCHES ] **********************************************************************");
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

    private boolean processTCPPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        log.info("**********************************************************************");
        IPv4 ipv4 = (IPv4) eth.getPayload();

        IDevice h1 = null;
        IDevice h2 = null;

        log.info("[ DEVICES ] **********************************************************************");
        for (IDevice device : deviceManagerService.getAllDevices()) {
            log.info(device.toString());
            if (Arrays.asList(device.getIPv4Addresses()).contains(ipv4.getDestinationAddress()) ||
                    Arrays.asList(device.getIPv4Addresses()).contains(ipv4.getSourceAddress())) {
                log.info(Arrays.toString(device.getIPv4Addresses()) + " contains either " + ipv4.getSourceAddress().toString() + " or " + ipv4.getDestinationAddress().toString());
                if (h1 == null) {
                    h1 = device;
                } else {
                    h2 = device;
                }
            }
        }

        if (isHostsOnSameSwitch(h1, h2, switchService)) {
            return true;
        }

        log.info("Not Done!");
        TCP tcp = (TCP)ipv4.getPayload();

        return false;
    }

    private void sendARPPacket(IOFSwitch iofSwitch, ArpRequestInfo arpInfo) {
        // First, we create a Eth header
        Ethernet l2 = new Ethernet();
        l2.setSourceMACAddress(arpInfo.senderMac);
        l2.setDestinationMACAddress(arpInfo.destinationMac);
        l2.setEtherType(EthType.ARP);


        // Set as ARP
        ARP arp = new ARP()
                .setHardwareType(ARP.HW_TYPE_ETHERNET)
                .setProtocolType(ARP.PROTO_TYPE_IP)
                .setHardwareAddressLength((byte) 6)
                .setProtocolAddressLength((byte) 4)
                .setSenderHardwareAddress(arpInfo.senderMac)
                .setSenderProtocolAddress(arpInfo.senderIp)
                .setOpCode(ARP.OP_REPLY)
                .setTargetHardwareAddress(arpInfo.targetMac)
                .setTargetProtocolAddress(arpInfo.targetIp);


        // Set the payloads
        l2.setPayload(arp);

        // Serialize
        byte[] serializedData = l2.serialize();

        OFPacketOut po = iofSwitch.getOFFactory().buildPacketOut()
                .setData(serializedData)
                .setActions(Collections.singletonList((OFAction) iofSwitch.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                .setInPort(OFPort.CONTROLLER)
                .build();

        log.info("Sent ARP");

        iofSwitch.write(po);
    }

	private void sendUDPPacket(IOFSwitch iofSwitch, PacketTopologyInfo packetTopologyInfo, Data data) {
        // First, we create a Eth header
        Ethernet l2 = new Ethernet();
        l2.setSourceMACAddress(packetTopologyInfo.getMacSource());
        l2.setDestinationMACAddress(packetTopologyInfo.getMacDest());
        l2.setEtherType(EthType.IPv4);

        // Then, the Payload
        IPv4 l3 = new IPv4();
        l3.setSourceAddress(packetTopologyInfo.getIpSource());
        l3.setDestinationAddress(packetTopologyInfo.getIpDest());
        l3.setTtl((byte) 64);
        l3.setProtocol(IpProtocol.UDP);


        // Set as UDP
        UDP l4 = new UDP();
        l4.setSourcePort(TransportPort.of(packetTopologyInfo.getPortSource()));
        l4.setDestinationPort(TransportPort.of(packetTopologyInfo.getPortDest()));


        // Set the payloads
        l2.setPayload(l3);
        l3.setPayload(l4);
        l4.setPayload(data);

        // Serialize
        byte[] serializedData = l2.serialize();

        OFPacketOut po = iofSwitch.getOFFactory().buildPacketOut()
                .setData(serializedData)
                .setActions(Collections.singletonList((OFAction) iofSwitch.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                .setInPort(OFPort.CONTROLLER)
                .build();

        iofSwitch.write(po);
    }

	private boolean isPortLANSync(int dstPort, int srcPort) {
	    if (NO_ONLINE_MODE && (srcPort == NO_ONLINE_PORT_NUMBER || dstPort == NO_ONLINE_PORT_NUMBER))
	        return true;

	    return (dstPort > 17500 && dstPort < 17600 && srcPort > 17500 && srcPort < 17600);
    }

    private class ArpRequestInfo {
	    public MacAddress senderMac, targetMac, destinationMac;
	    public IPv4Address senderIp, targetIp;

        public ArpRequestInfo(MacAddress destinationMac, MacAddress senderMac, MacAddress targetMac, IPv4Address senderIp, IPv4Address targetIp) {
            this.senderMac = senderMac;
            this.targetMac = targetMac;
            this.senderIp = senderIp;
            this.targetIp = targetIp;
            this.destinationMac = destinationMac;
        }
    }

    private class PacketTopologyInfo {
	    private MacAddress macSource;
        private MacAddress macDest;
	    private IPv4Address ipSource;
        private IPv4Address ipDest;
	    private int portSource;
        private int portDest;

        public PacketTopologyInfo(MacAddress macSource, MacAddress macDest, IPv4Address ipSource, IPv4Address ipDest, int portSource, int portDest) {
            this.setMacSource(macSource);
            this.setMacDest(macDest);
            this.setIpSource(ipSource);
            this.setIpDest(ipDest);
            this.setPortSource(portSource);
            this.setPortDest(portDest);
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

}
