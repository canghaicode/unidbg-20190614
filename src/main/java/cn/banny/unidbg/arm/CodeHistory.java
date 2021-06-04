package cn.banny.unidbg.arm;

import capstone.Capstone;
import cn.banny.unidbg.Emulator;

public class CodeHistory {

    public final long address;
    private final int size;
    final boolean thumb;
    CodeHistory(long address, int size, boolean thumb) {
        this.address = address;
        this.size = size;
        this.thumb = thumb;
    }

    Capstone.CsInsn disassemble(Emulator emulator) {
        return emulator.disassemble(address, emulator.getUnicorn().mem_read(address, size), thumb)[0];
    }

}
