package cn.banny.unidbg.arm.context;

import cn.banny.unidbg.pointer.UnicornPointer;

public abstract class AbstractRegisterContext implements RegisterContext {

    @Override
    public final int getIntArg(int index) {
        return (int) getLongArg(index);
    }

    @Override
    public final long getLongArg(int index) {
        UnicornPointer pointer = getPointerArg(index);
        return pointer == null ? 0 : pointer.peer;
    }

}
