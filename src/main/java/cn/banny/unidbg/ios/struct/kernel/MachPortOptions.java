package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortOptions extends UnicornStructure {

    public MachPortOptions(Pointer p) {
        super(p);
    }

    public int flags; /* Flags defining attributes for port */
    public MachPortLimits mpl; /* Message queue limit for port */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("flags", "mpl");
    }

}
