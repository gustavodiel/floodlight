package tcc.diel.dropbox;

import org.projectfloodlight.openflow.types.MacAddress;

public class FakeIPMatch {

    String fakeIP;
    String realIP;

    MacAddress fakeMacAddress;
    MacAddress realMacAddress;

    public FakeIPMatch(String fakeIP, String realIP) {
        this.fakeIP = fakeIP;
        this.realIP = realIP;
    }

    @Override
    public String toString() {
        return "Real IP: " + realIP + ", Fake IP: " + fakeIP + "  |  Real Mac: " + realMacAddress + ", Fake Mac: " + fakeMacAddress;
    }
}
