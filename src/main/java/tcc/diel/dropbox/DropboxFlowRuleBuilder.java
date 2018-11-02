package tcc.diel.dropbox;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.util.FlowModUtils;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class DropboxFlowMatch {
    DatapathId sw;
    OFFlowModCommand command;
    Match match;
}

public class DropboxFlowRuleBuilder {

    protected static final Logger log = LoggerFactory.getLogger(DropboxFlowRuleBuilder.class);

    static final int IDLE_TIMEOUT = 5;
    static final int HARD_TIMEOUT = 0;
    static final int PRIORITY = 100;

    static final long COOKIE = 4527;
    /**
     * Writes a OFFlowMod to a switch.
     * @param sw The switch tow rite the flowmod to.
     * @param command The FlowMod actions (add, delete, etc).
     * @param match The OFMatch structure to write.
     * @param outPort The switch port to output it to.
     */
    public static void writeFlowMod(IOFSwitch sw, OFFlowModCommand command,
                              Match match, OFPort outPort, List<OFAction> al) {

        OFFlowMod.Builder fmb;
        if (command == OFFlowModCommand.DELETE) {
            fmb = sw.getOFFactory().buildFlowDelete();
        } else {
            fmb = sw.getOFFactory().buildFlowAdd();
        }
        fmb.setMatch(match);
        fmb.setCookie((U64.of(COOKIE)));
        fmb.setIdleTimeout(IDLE_TIMEOUT);
        fmb.setHardTimeout(HARD_TIMEOUT);
        fmb.setPriority(PRIORITY);
        fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);
        Set<OFFlowModFlags> sfmf = new HashSet<>();

        if (command != OFFlowModCommand.DELETE) {
            sfmf.add(OFFlowModFlags.SEND_FLOW_REM);
        }

        fmb.setFlags(sfmf);

        FlowModUtils.setActions(fmb, al, sw);

        log.info("{} {} flow mod {}",
                new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });


        // and write it out
        sw.write(fmb.build());
    }
}
