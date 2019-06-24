package tcc.diel.dropbox;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;

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


	//                     Fake IP  Match
    static final HashMap<String, FakeIPMatch> ARP_TABLE = new HashMap<>();
    static final HashMap<String, String> FAKED_IPS = new HashMap<>();

	static IDeviceService deviceManagerService;
	
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

	                if (DropboxHelper.isTCPLANSync(tcp, ipv4)){
	                	return DropboxResponses.LANSYNC;
	                }
	                 
	            } else if (ipv4.getProtocol() == IpProtocol.UDP) {
	            	
	                UDP udp = (UDP) ipv4.getPayload();
	                
	                if (DropboxHelper.isUDPLANSync(udp, ipv4)) {
	                	return DropboxResponses.LANSYNC;
	                }
	            }
	            
	        } else if (eth.getEtherType() == EthType.ARP) {

	            return DropboxResponses.ARP;
	        }
		
		return DropboxResponses.CONTINUE;
	}

	public void processARPRequest(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        ARP arp = (ARP) eth.getPayload();

        IPv4Address target = arp.getTargetProtocolAddress();
        IPv4Address sender = arp.getSenderProtocolAddress();

        FakeIPMatch match = FakeIPMatchHelper.getMatchForFakeIp(target);

        if (match != null) {
            MacAddress macTarget = match.fakeMacAddress;
            if (macTarget == null) {
                macTarget = match.fakeMacAddress = FakeIPMatchHelper.generateMacAddressForFakeIp(target);
            }

            // macSender    macTarget   macDest ipSender    ipTarget
            ARPPakageCreator info = new ARPPakageCreator(macTarget, eth.getSourceMACAddress(), eth.getSourceMACAddress(), target, sender);

            info.sendARPPacket(iofSwitch);


        }
    }

	public boolean shouldDropPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        IPv4 ipv4 = (IPv4) eth.getPayload();

        DropboxAnalyzer.deviceManagerService = deviceManagerService;

        if (packageIsTCP(ipv4.getPayload())) {
            return processTCPPackage(eth, packetIn, iofSwitch, topologyService, floodlightProviderService, switchService, routingEngineService, linkService);
        } else {
            processUDPPackage(eth, packetIn, iofSwitch, topologyService, floodlightProviderService, switchService, routingEngineService, linkService);
            return false;
        }
	}

	private boolean packageIsTCP(IPacket data) {
	    return data instanceof TCP;
    }

	private void processUDPPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService) {
        IPv4 ipv4 = (IPv4) eth.getPayload();

        UDP udp = (UDP)ipv4.getPayload();

	    Data packageData = (Data) udp.getPayload();

        if (!ipv4.getDestinationAddress().toString().equals("255.255.255.255")) {
            return;
        }

        // for each network create a fake ip.
        FakeIPMatchHelper.generateFakeMatchForEachDevice(ipv4.getSourceAddress().toString(), eth.getSourceMACAddress(), switchService);


        for (DatapathId switchId : switchService.getAllSwitchDpids()){
            IOFSwitch toSendSwitch = switchService.getSwitch(switchId);
            if (!topologyService.isInSameCluster(toSendSwitch.getId(), iofSwitch.getId())) {

                FakeIPMatch match = FakeIPMatchHelper.getMatchForIp(ipv4.getSourceAddress(), eth.getSourceMACAddress());

                if (match == null) {
                    return;
                }

                UDPPackageCreator info = new UDPPackageCreator(
                        match.fakeMacAddress != null ? match.fakeMacAddress : eth.getSourceMACAddress(),
                        eth.getDestinationMACAddress(),
                        IPv4Address.of(match.fakeIP),
                        IPv4Address.of("255.255.255.255"),
                        udp.getSourcePort().getPort(),
                        udp.getDestinationPort().getPort());

                info.sendUDPPacket(toSendSwitch, eth, packageData);
            }
        }
    }

    private boolean processTCPPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService) {
        IPv4 ipv4 = (IPv4) eth.getPayload();

        IDevice h1 = DropboxHelper.findDeviceFromIP(ipv4.getDestinationAddress());
        IDevice h2 = DropboxHelper.findDeviceFromIP(ipv4.getSourceAddress());

        if (DropboxHelper.isHostsOnSameSwitch(h1, h2)) {
            return false;
        }

        TCP tcp = (TCP)ipv4.getPayload();

        FakeIPMatch matchDest = FakeIPMatchHelper.getMatchForIp(ipv4.getDestinationAddress(), eth.getDestinationMACAddress());

        IDevice destinationHost = DropboxHelper.findDeviceFromIP(IPv4Address.of(matchDest.realIP));

        try {
            SwitchPort[] ports = destinationHost.getAttachmentPoints();

            if (ports.length > 0) {
                DatapathId switchId = ports[0].getNodeId();

                IOFSwitch iofSwitch1 = switchService.getSwitch(switchId);

                FakeIPMatch matchSource = FakeIPMatchHelper.getMatchForIp(ipv4.getSourceAddress(), eth.getSourceMACAddress());

                TCPPackageCreator tcpPackage = new TCPPackageCreator(
                        matchSource.fakeMacAddress,
                        matchDest.realMacAddress,
                        IPv4Address.of(matchSource.fakeIP),
                        IPv4Address.of(matchDest.realIP),
                        tcp);

                tcpPackage.sendTCPPacket(iofSwitch1, ipv4, (Data) tcp.getPayload());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }


}
