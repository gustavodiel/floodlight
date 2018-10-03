package tcc.diel.dropbox;

import org.projectfloodlight.openflow.types.MacAddress;

public class FakeIPMatch {

    String FakeIP;
    String RealIP;

    MacAddress macAddress;

    public FakeIPMatch(String fakeIP, String realIP) {
        FakeIP = fakeIP;
        RealIP = realIP;
    }
}
