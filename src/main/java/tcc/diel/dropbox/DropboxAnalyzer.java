package tcc.diel.dropbox;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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


	private static HashMap<IPv4Address, MacAddress> arpTable = new HashMap<>();
	
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
        IPv4Address sender = arp.getSenderProtocolAddress();

        log.info(target.toString());
        log.info(iofSwitch.toString());

        if (arpTable.containsKey(target)) {
            MacAddress macTarget = arpTable.get(target);
            if (macTarget == null) {
                arpTable.put(target, generateMacAddressForFakeIp(target));
            }
            macTarget = arpTable.get(target);

            // macSender    macTarget   macDest ipSender    ipTarget
                ARPPakageCreator info = new ARPPakageCreator( macTarget, eth.getSourceMACAddress(), eth.getSourceMACAddress(), target, sender);

            log.info(eth.getSourceMACAddress().toString());

            info.sendARPPacket(iofSwitch);

        }
    }

    private MacAddress generateMacAddressForFakeIp(IPv4Address iPv4Address) {
	    String strMac = "Ba:ba:ca:";
	    String last = String.format("%06d", arpTable.size());

        last = last.substring(0, 2) + ":" + last.substring(2, 4) + ":" + last.substring(4, 6);

        String finalMac = strMac + last;

        log.info(finalMac);

        return MacAddress.of(finalMac);
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

                UDPPackageCreator info = new UDPPackageCreator(
                        MacAddress.FULL_MASK,
                        eth.getDestinationMACAddress(),
                        createFakeIpForSwitch(ipv4.getSourceAddress(), toSendSwitch),
                        IPv4Address.of("255.255.255.255"),
                        6695,
                        12312);

                info.sendUDPPacket(toSendSwitch, packageData);
            }

        }
    }

    private IPv4Address createFakeIpForSwitch(IPv4Address iPv4Address, IOFSwitch iofSwitch) {

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

        IDevice destinationHost = findDeviceFromIP(ipv4.getDestinationAddress(), deviceManagerService);

        SwitchPort[] ports = destinationHost.getAttachmentPoints();

        if (ports.length > 0) {
            DatapathId switchId = ports[0].getNodeId();

            IOFSwitch iofSwitch1 = switchService.getSwitch(switchId);

            TCPPackageCreator tcpPackage = new TCPPackageCreator(eth.getSourceMACAddress(), destinationHost.getMACAddress(), createFakeIpForSwitch(ipv4.getSourceAddress(), iofSwitch1), ipv4.getDestinationAddress(), tcp);
            tcpPackage.sendTCPPacket(iofSwitch1, (Data)tcp.getPayload());
        }

        return false;
    }

	private boolean isPortLANSync(int dstPort, int srcPort) {
	    if (NO_ONLINE_MODE && (srcPort == NO_ONLINE_PORT_NUMBER || dstPort == NO_ONLINE_PORT_NUMBER))
	        return true;

	    return (dstPort > 17500 && dstPort < 17600 && srcPort > 17500 && srcPort < 17600);
    }

    private IDevice findDeviceFromIP(IPv4Address ip, IDeviceService deviceManagerService) {
        // Fetch all known devices
        Collection<? extends IDevice> allDevices = deviceManagerService.getAllDevices();

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
