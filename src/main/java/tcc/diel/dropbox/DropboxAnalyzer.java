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
	private static HashMap<String, FakeIPMatch> arpTable = new HashMap<>();
	private static HashMap<String, String> fakedIps = new HashMap<>();

	private static boolean first = true;

	IDeviceService deviceManagerService;
	
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

	                if (this.isTCPLANSync(tcp, ipv4)){
	                	return DropboxResponses.LANSYNC;
	                }
	                 
	            } else if (ipv4.getProtocol() == IpProtocol.UDP) {
	            	
	                UDP udp = (UDP) ipv4.getPayload();
	                
	                if (this.isUDPLANSync(udp, ipv4)) {
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

        log.info("ARP request for {} to {}", target.toString(), sender.toString());

        FakeIPMatch match = getMatchForFakeIp(target);

        if (match != null) {
            MacAddress macTarget = match.fakeMacAddress;
            if (macTarget == null) {
                macTarget = match.fakeMacAddress = generateMacAddressForFakeIp(target);
            }

            // macSender    macTarget   macDest ipSender    ipTarget
            ARPPakageCreator info = new ARPPakageCreator(macTarget, eth.getSourceMACAddress(), eth.getSourceMACAddress(), target, sender);

            log.info(eth.getSourceMACAddress().toString());

            info.sendARPPacket(iofSwitch);

            log.info("SEND ARP!!!!");

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

    private String generateFakeIpForSubnetworkOf(IPv4Address iPv4Address) {
        String[] components = iPv4Address.toString().split("\\.");
        log.info(iPv4Address.toString());
        String base = components[0] + '.' + components[1] + '.' + components[2] + '.';
        int start = Integer.parseInt(components[3]) + 1;
        while (start < 254) {
            String currentIp = base + start;
            log.info("Testing: " + currentIp);
            if (findDeviceFromIP(IPv4Address.of(currentIp)) == null) {
                return currentIp;
            }
            start++;
        }
        return base + start;
    }

	public boolean shouldDropPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService, IDeviceService deviceManagerService) {
        log.info("Processing LANSync package!");

        IPv4 ipv4 = (IPv4) eth.getPayload();

        this.deviceManagerService = deviceManagerService;

        if (packageIsTCP(ipv4.getPayload())) {
            log.info("*** It is TCP ***********************************************************");
            return processTCPPackage(eth, packetIn, iofSwitch, topologyService, floodlightProviderService, switchService, routingEngineService, linkService);
        } else {
            log.info("*** It is UDP");
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
        generateFakeMatchForEachDevice(ipv4.getSourceAddress().toString(), eth.getSourceMACAddress(), switchService);


        for (DatapathId switchId : switchService.getAllSwitchDpids()){
            IOFSwitch toSendSwitch = switchService.getSwitch(switchId);
            if (!topologyService.isInSameCluster(toSendSwitch.getId(), iofSwitch.getId())) {

                FakeIPMatch match = getMatchForIp(ipv4.getSourceAddress(), eth.getSourceMACAddress());

                if (match == null) {
                    log.info("No match for {}!", ipv4.getSourceAddress());
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

    private void generateFakeMatchForEachDevice(String realIp, MacAddress realmac, IOFSwitchService switchService) {
        Collection<? extends IDevice> allDevices = deviceManagerService.getAllDevices();
        IDevice realDevice = findDeviceFromIP(IPv4Address.of(realIp));
        for (IDevice device : allDevices) {
            if (realDevice == device || isHostsOnSameSwitch(device, realDevice, switchService)) continue;

            for (IPv4Address ip : device.getIPv4Addresses()) {
                boolean alreadyFaked = fakedIps.containsKey(ip.toString());
                log.info("Has {} faked? {}", ip.toString(), alreadyFaked);

                boolean isBanned = isBannedIp(ip);
                log.info("Is {} banned? {}", ip, isBanned);

                if (!(alreadyFaked || isBanned)) {
                    createFakeMatchForIp(ip, IPv4Address.of(realIp), realmac);
                }
            }
        }
    }

    private boolean isBannedIp(IPv4Address ip) {
	    return ip.toString().equals("10.0.0.1") || ip.toString().equals("10.0.0.2");
    }

    private FakeIPMatch createFakeMatchForIp(IPv4Address ipToConnect, IPv4Address realIp, MacAddress realMac) {
//        if (first) {
//            first = false;
//
//            FakeIPMatch aliceMatch = new FakeIPMatch("10.0.1.4", "10.0.2.2");
//            aliceMatch.realMacAddress = MacAddress.of("00:00:00:00:02:02");
//            aliceMatch.fakeMacAddress = MacAddress.of("ba:ba:ca:00:02:02");
//
//            FakeIPMatch dielMatch = new FakeIPMatch("10.0.2.4", "10.0.1.2");
//            dielMatch.realMacAddress = MacAddress.of("00:00:00:00:01:02");
//            dielMatch.fakeMacAddress = MacAddress.of("ba:ba:ca:00:01:02");
//
//            arpTable.put("10.0.1.4", aliceMatch);
//            arpTable.put("10.0.2.4", dielMatch);
//
//            log.info("Rules added for Alice, Bob and Diel!");
//        }

        // If we already have a real ip with a match
//        for (FakeIPMatch match : arpTable.values()) {
//            if (match.realIP.equals(realIp.toString())) {
//                return match;
//            }
//        }

        // If we already have this fake ip
//        if (arpTable.containsKey(realIp.toString())) {
//            return arpTable.get(realIp.toString());
//        } else {
//            log.error("NOP! {}", realIp.toString());
//        }

        // Criate a new match
        String fakeIp = generateFakeIpForSubnetworkOf(ipToConnect);

        FakeIPMatch fakeIPMatch = new FakeIPMatch(fakeIp, realIp.toString());

        log.info("Generated IP {} for real {}!", fakeIp, realIp);

        arpTable.put(fakeIp, fakeIPMatch);
        fakedIps.put(realIp.toString(), fakeIp);

        fakeIPMatch.fakeMacAddress = generateMacAddressForFakeIp(realIp);
        fakeIPMatch.realMacAddress = realMac;

        return fakeIPMatch;
    }

    private boolean isHostsOnSameSwitch(IDevice host1, IDevice host2, IOFSwitchService switchService){
	    if (host1 == null || host2 == null) { // How could this be?
            log.error("Hosts Null!!");
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

    private boolean processTCPPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService, IFloodlightProviderService floodlightProviderService, IOFSwitchService switchService, IRoutingService routingEngineService, ILinkDiscoveryService linkService) {
        IPv4 ipv4 = (IPv4) eth.getPayload();

        IDevice h1 = findDeviceFromIP(ipv4.getDestinationAddress());
        IDevice h2 = findDeviceFromIP(ipv4.getSourceAddress());

//        for (IDevice device : deviceManagerService.getAllDevices()) {
//            log.info(device.toString());
//            if (Arrays.asList(device.getIPv4Addresses()).contains(ipv4.getDestinationAddress()) ||
//                    Arrays.asList(device.getIPv4Addresses()).contains(ipv4.getSourceAddress())) {
//                if (h1 == null) {
//                    h1 = device;
//                } else {
//                    h2 = device;
//                }
//            }
//        }

        if (isHostsOnSameSwitch(h1, h2, switchService)) {
            return false;
        }

        TCP tcp = (TCP)ipv4.getPayload();

        FakeIPMatch matchDest = getMatchForIp(ipv4.getDestinationAddress(), eth.getDestinationMACAddress());
        IDevice destinationHost = findDeviceFromIP(IPv4Address.of(matchDest.realIP));

        try {
            SwitchPort[] ports = destinationHost.getAttachmentPoints();

            if (ports.length > 0) {
                DatapathId switchId = ports[0].getNodeId();

                IOFSwitch iofSwitch1 = switchService.getSwitch(switchId);

                FakeIPMatch matchSource = getMatchForIp(ipv4.getSourceAddress(), eth.getSourceMACAddress());

                log.info("************ MATCH FOR {} AND {}!!!", ipv4.getSourceAddress(), ipv4.getDestinationAddress());
                log.info("************ WITH MAC FOR {} AND {}!!!", matchSource.fakeMacAddress, destinationHost.getMACAddress());

                log.info("************ MATCH SOURCE: {} !!!", matchSource);
                log.info("************ MATCH DESTINATION: {} !!!",matchDest);

                TCPPackageCreator tcpPackage = new TCPPackageCreator(
                        matchSource.fakeMacAddress,
                        matchDest.realMacAddress,
                        IPv4Address.of(matchSource.fakeIP),
                        IPv4Address.of(matchDest.realIP),
                        tcp);

                tcpPackage.sendTCPPacket(iofSwitch1, ipv4, (Data) tcp.getPayload());
            }
        } catch (Exception e) {
            log.info("ERROOOOOOOOOOOOOOOOOOOOOOOOOOOOO");
            e.printStackTrace();
        }

        return true;
    }

    private boolean isMacFake(MacAddress macAddress) {
	    return macAddress.toString().startsWith("ba:ba:ca", 0);
    }

    private FakeIPMatch getMatchForIp(IPv4Address iPv4Address, MacAddress macAddress) {
	    FakeIPMatch match = getMatchForFakeIp(iPv4Address);
        if (match == null) {
            match = getMatchForRealIp(iPv4Address);
        }
//        if (match == null) {
//            match = createFakeMatchForIpOnSwitch(iPv4Address, macAddress, null);
//        }
        return match;
    }

    private FakeIPMatch getMatchForFakeIp(IPv4Address iPv4Address) {
	    if (arpTable.containsKey(iPv4Address.toString())) {
	        return arpTable.get(iPv4Address.toString());
        }
        return null;
    }

    private FakeIPMatch getMatchForRealIp(IPv4Address iPv4Address) {
        for (FakeIPMatch match : arpTable.values()) {
            if (match.realIP.equals(iPv4Address.toString())) {
                return match;
            }
        }
        return null;
    }

    private boolean isUDPLANSync(UDP udp, IPv4 ip) {
        int srcPort = udp.getSourcePort().getPort();
        int dstPort = udp.getDestinationPort().getPort();

        if (NO_ONLINE_MODE && (srcPort == NO_ONLINE_PORT_NUMBER || dstPort == NO_ONLINE_PORT_NUMBER))
            return true;

        return ((dstPort >= 17500 && dstPort <= 17600) || (srcPort >= 17500 && srcPort <= 17600));
    }


    private boolean isTCPLANSync(TCP tcp, IPv4 ip) {
        int srcPort = tcp.getSourcePort().getPort();
        int dstPort = tcp.getDestinationPort().getPort();

        if (NO_ONLINE_MODE && (srcPort == NO_ONLINE_PORT_NUMBER || dstPort == NO_ONLINE_PORT_NUMBER))
            return true;

        return ((dstPort >= 17500 && dstPort <= 17600) || (srcPort >= 17500 && srcPort <= 17600));
    }

    private IDevice findDeviceFromIP(IPv4Address ip) {
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
