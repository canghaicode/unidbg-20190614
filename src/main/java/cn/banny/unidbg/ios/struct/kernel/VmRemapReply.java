package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRemapReply extends UnicornStructure {

    public VmRemapReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;

    public int pad;
    public int retCode;
    public int target_address1;
    public int target_address2;
    public int cur_protection;
    public int max_protection;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "pad", "retCode", "target_address1", "target_address2", "cur_protection", "max_protection");
    }

}
