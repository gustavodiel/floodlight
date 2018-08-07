package tcc.diel.dropbox;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

public class DropboxAnalyzer {
	
	protected static final Logger log = LoggerFactory.getLogger(DropboxAnalyzer.class);
	
	public DropboxAnalyzer() {
		// TODO Auto-generated constructor stub
	}
	
	public boolean isEthernetPackageLANSync(Ethernet eth) {
		
		 if (eth.getEtherType() == EthType.IPv4) {
	            /* Get the payload */
	            IPv4 ipv4 = (IPv4) eth.getPayload();
	            
	            /* IPv4 Options */
	            byte[] ipOptions = ipv4.getOptions();
	            
	            /* 
	             * Here we check if it's TCP or UDP
	             */
	            if (ipv4.getProtocol() == IpProtocol.TCP) {
	            	
	                TCP tcp = (TCP) ipv4.getPayload();
	  
	                int srcPort = tcp.getSourcePort().getPort();
	                int dstPort = tcp.getDestinationPort().getPort();

	                log.info("TCP SOURCE: {}:{}", ipv4.getSourceAddress(), srcPort);
	                log.info("TCP DESTINATION: {}:{}", ipv4.getDestinationAddress(), dstPort);
	                
	                if (dstPort > 17500 && dstPort < 17600 && srcPort > 17500 && srcPort < 17600) {
	                	return true;
	                }
	                 
	            } else if (ipv4.getProtocol() == IpProtocol.UDP) {
	            	
	                UDP udp = (UDP) ipv4.getPayload();
	  
	                int srcPort = udp.getSourcePort().getPort();
	                int dstPort = udp.getDestinationPort().getPort();

	                log.info("UDP: {} {}", srcPort, dstPort);
	                
	                if (dstPort > 17500 && dstPort < 17600 && srcPort > 17500 && srcPort < 17600) {
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

}
