package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskGetExceptionPortsReply extends UnicornStructure {

    public TaskGetExceptionPortsReply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int[] header = new int[32];
    public int masksCnt;
    public byte[] reserved = new byte[0x100];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "header", "masksCnt", "reserved");
    }

}
