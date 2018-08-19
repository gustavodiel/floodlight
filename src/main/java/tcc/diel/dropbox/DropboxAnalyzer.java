package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.*;
import org.python.antlr.ast.Str;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
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
	
	public DropboxAnalyzer() {
		// TODO Auto-generated constructor stub
	}
	
	public boolean isEthernetPackageLANSync(Ethernet eth) {
		
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
	                	return true;
	                }
	                 
	            } else if (ipv4.getProtocol() == IpProtocol.UDP) {
	            	
	                UDP udp = (UDP) ipv4.getPayload();
	  
	                int srcPort = udp.getSourcePort().getPort();
	                int dstPort = udp.getDestinationPort().getPort();

	                log.info("UDP: {} {}", srcPort, dstPort);
	                
	                if (this.isPortLANSync(dstPort, srcPort)) {
	                	return true;
	                }
	            }
	            
	        } else if (eth.getEtherType() == EthType.ARP) {
	        	
	            ARP arp = (ARP) eth.getPayload();
	            
	            log.info("ARP: {}", arp.toString());
	  
	        } else {
	            log.info("Nao Sei: {}", eth.getEtherType());
	        }
		
		return false;
	}

	public void processLANSyncPackage(Ethernet eth, OFPacketIn packetIn, IOFSwitch iofSwitch, ITopologyService topologyService) {
        log.info("Processing LANSync package!");

        IPv4 ipv4 = (IPv4) eth.getPayload();

        UDP udp = (UDP) ipv4.getPayload();

        Data packageData = (Data) udp.getPayload();

        log.info(String.valueOf(udp.getSourcePort()));

        if (udp.getSourcePort().getPort() == 6695) {
            log.info("Our generated package! Staph");
            return;
        }

        Set<DatapathId> cluster = topologyService.getSwitchesInCluster(iofSwitch.getId());
        Set<DatapathId> clusterIdsInArchipelago = topologyService.getClusterIdsInArchipelago(iofSwitch.getId());


        log.info("In cluster:");
        log.info(cluster.toString());

        log.info("In archipelago:");
        log.info(clusterIdsInArchipelago.toString());

        // Duplicate package

        // First, we create a Eth header
        Ethernet l2 = new Ethernet();
        l2.setSourceMACAddress(eth.getSourceMACAddress());
        l2.setDestinationMACAddress(eth.getDestinationMACAddress());
        l2.setEtherType(EthType.IPv4);

        // Then, the Payload
        IPv4 l3 = new IPv4();
        l3.setSourceAddress(ipv4.getSourceAddress());
        l3.setDestinationAddress(ipv4.getDestinationAddress());
        l3.setTtl((byte) 64);
        l3.setProtocol(IpProtocol.UDP);


        // Set as UDP
        UDP l4 = new UDP();
        l4.setSourcePort(TransportPort.of(6695));
        l4.setDestinationPort(TransportPort.of(12312));

        // Write the data
        Data l7 = new Data();
        l7.setData(packageData.getData());


        // Set the payloads
        l2.setPayload(l3);
        l3.setPayload(l4);
        l4.setPayload(l7);

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

}
