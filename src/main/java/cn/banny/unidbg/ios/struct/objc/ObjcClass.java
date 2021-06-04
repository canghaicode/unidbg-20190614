package cn.banny.unidbg.ios.struct.objc;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * objc_class
 */
public class ObjcClass extends UnicornStructure {

    public ObjcClass(Pointer p) {
        super(p);
    }

    public Pointer isa;
    public Pointer superClass;
    public Pointer cache;
    public Pointer vtable;
    public Pointer data;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("isa", "superClass", "cache", "vtable", "data");
    }

    public void setData(ClassRW classRW) {
        data = classRW.getPointer();
    }

}
