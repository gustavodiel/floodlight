package tcc.diel.dropbox;

import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.devicemanager.IDevice;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

import java.util.Collection;

class FakeIPMatchHelper {
    static FakeIPMatch getMatchForIp(IPv4Address iPv4Address, MacAddress macAddress) {
        FakeIPMatch match = getMatchForFakeIp(iPv4Address);
        if (match == null) {
            match = getMatchForRealIp(iPv4Address);
        }
//        if (match == null) {
//            match = createFakeMatchForIpOnSwitch(iPv4Address, macAddress, null);
//        }
        return match;
    }

    static FakeIPMatch getMatchForFakeIp(IPv4Address iPv4Address) {
        if (DropboxAnalyzer.ARP_TABLE.containsKey(iPv4Address.toString())) {
            return DropboxAnalyzer.ARP_TABLE.get(iPv4Address.toString());
        }
        return null;
    }

    static FakeIPMatch getMatchForRealIp(IPv4Address iPv4Address) {
        for (FakeIPMatch match : DropboxAnalyzer.ARP_TABLE.values()) {
            if (match.realIP.equals(iPv4Address.toString())) {
                return match;
            }
        }
        return null;
    }

    static MacAddress generateMacAddressForFakeIp(IPv4Address iPv4Address) {
        String strMac = "Ba:ba:ca:";
        String last = String.format("%06d", DropboxAnalyzer.ARP_TABLE.size());

        last = last.substring(0, 2) + ":" + last.substring(2, 4) + ":" + last.substring(4, 6);

        String finalMac = strMac + last;

        return MacAddress.of(finalMac);
    }

    static String generateFakeIpForSubnetworkOf(IPv4Address iPv4Address) {
        String[] components = iPv4Address.toString().split("\\.");
        String base = components[0] + '.' + components[1] + '.' + components[2] + '.';
        int start = Integer.parseInt(components[3]) + 1;
        while (start < 254) {
            String currentIp = base + start;
            if (DropboxHelper.findDeviceFromIP(IPv4Address.of(currentIp)) == null) {
                return currentIp;
            }
            start++;
        }
        return base + start;
    }

    static void generateFakeMatchForEachDevice(String realIp, MacAddress realmac, IOFSwitchService switchService) {
        Collection<? extends IDevice> allDevices = DropboxAnalyzer.deviceManagerService.getAllDevices();
        IDevice realDevice = DropboxHelper.findDeviceFromIP(IPv4Address.of(realIp));
        for (IDevice device : allDevices) {
            if (realDevice == device || DropboxHelper.isHostsOnSameSwitch(device, realDevice)) continue;

            for (IPv4Address ip : device.getIPv4Addresses()) {
                boolean alreadyFaked = DropboxAnalyzer.FAKED_IPS.containsKey(ip.toString());

                if (!alreadyFaked && !DropboxHelper.isBannedIp(ip)) {
                    createFakeMatchForIp(ip, IPv4Address.of(realIp), realmac);
                }
            }
        }
    }

    static FakeIPMatch createFakeMatchForIp(IPv4Address ipToConnect, IPv4Address realIp, MacAddress realMac) {

        // Criate a new match
        String fakeIp = FakeIPMatchHelper.generateFakeIpForSubnetworkOf(ipToConnect);

        FakeIPMatch fakeIPMatch = new FakeIPMatch(fakeIp, realIp.toString());

        DropboxAnalyzer.ARP_TABLE.put(fakeIp, fakeIPMatch);
        DropboxAnalyzer.FAKED_IPS.put(realIp.toString(), fakeIp);

        fakeIPMatch.fakeMacAddress = FakeIPMatchHelper.generateMacAddressForFakeIp(realIp);
        fakeIPMatch.realMacAddress = realMac;

        return fakeIPMatch;
    }


}
