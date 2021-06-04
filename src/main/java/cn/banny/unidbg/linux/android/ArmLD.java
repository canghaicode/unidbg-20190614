package cn.banny.unidbg.linux.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ArmSvc;
import cn.banny.unidbg.linux.LinuxModule;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.Dlfcn;
import cn.banny.unidbg.spi.InitFunction;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.IOException;
import java.util.Arrays;

public class ArmLD extends Dlfcn {

    private static final Log log = LogFactory.getLog(ArmLD.class);

    private Unicorn unicorn;

    ArmLD(Unicorn unicorn, SvcMemory svcMemory) {
        super(svcMemory);
        this.unicorn = unicorn;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        if ("libdl.so".equals(libraryName)) {
            log.debug("link " + symbolName + ", old=0x" + Long.toHexString(old));
            switch (symbolName) {
                case "dlerror":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator emulator) {
                            return error.peer;
                        }
                    }).peer;
                case "dlclose":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator emulator) {
                            long handle = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
                            if (log.isDebugEnabled()) {
                                log.debug("dlclose handle=0x" + Long.toHexString(handle));
                            }
                            return dlclose(emulator.getMemory(), handle);
                        }
                    }).peer;
                case "dlopen":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                        "push {r4-r7, lr}",
                                        "svc #0x" + Integer.toHexString(svcNumber),
                                        "pop {r7}", // manipulated stack in dlopen
                                        "cmp r7, #0",
                                        "subne lr, pc, #16", // jump to pop {r7}
                                        "bxne r7", // call init array
                                        "pop {r0, r4-r7, pc}")); // with return address
                                byte[] code = encoded.getMachineCode();
                                UnicornPointer pointer = svcMemory.allocate(code.length, "dlopen");
                                pointer.write(0, code, 0, code.length);
                                return pointer;
                            }
                        }
                        @Override
                        public long handle(Emulator emulator) {
                            Pointer filename = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int flags = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            if (log.isDebugEnabled()) {
                                log.debug("dlopen filename=" + filename.getString(0) + ", flags=" + flags);
                            }
                            return dlopen(emulator.getMemory(), filename.getString(0), emulator);
                        }
                    }).peer;
                case "dladdr":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator emulator) {
                            long addr = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
                            Pointer info = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            log.info("dladdr addr=0x" + Long.toHexString(addr) + ", info=" + info);
                            throw new UnicornException();
                        }
                    }).peer;
                case "dlsym":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator emulator) {
                            long handle = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
                            Pointer symbol = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            if (log.isDebugEnabled()) {
                                log.debug("dlsym handle=0x" + Long.toHexString(handle) + ", symbol=" + symbol.getString(0));
                            }
                            return dlsym(emulator.getMemory(), handle, symbol.getString(0));
                        }
                    }).peer;
                case "dl_unwind_find_exidx":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator emulator) {
                            Pointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            Pointer pcount = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            if (log.isDebugEnabled()) {
                                log.debug("dl_unwind_find_exidx pc" + pc + ", pcount=" + pcount);
                            }
                            return 0;
                        }
                    }).peer;
            }
        }
        return 0;
    }

    private long dlopen(Memory memory, String filename, Emulator emulator) {
        Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            Module module = memory.dlopen(filename, false);
            if (module == null) {
                pointer = pointer.share(-4); // return value
                pointer.setInt(0, 0);

                pointer = pointer.share(-4); // NULL-terminated
                pointer.setInt(0, 0);

                log.info("dlopen failed: " + filename);
                this.error.setString(0, "Resolve library " + filename + " failed");
                return 0;
            } else {
                pointer = pointer.share(-4); // return value
                pointer.setInt(0, (int) module.base);

                pointer = pointer.share(-4); // NULL-terminated
                pointer.setInt(0, 0);

                for (Module md : memory.getLoadedModules()) {
                    LinuxModule m = (LinuxModule) md;
                    if (!m.getUnresolvedSymbol().isEmpty()) {
                        continue;
                    }
                    for (InitFunction initFunction : m.initFunctionList) {
                        if (log.isDebugEnabled()) {
                            log.debug("[" + m.name + "]PushInitFunction: 0x" + Long.toHexString(initFunction.getAddress()));
                        }
                        pointer = pointer.share(-4); // init array
                        pointer.setInt(0, (int) initFunction.getAddress());
                    }
                    m.initFunctionList.clear();
                }

                return module.base;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            unicorn.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) pointer).peer);
        }
    }

    private int dlclose(Memory memory, long handle) {
        if (memory.dlclose(handle)) {
            return 0;
        } else {
            this.error.setString(0, "dlclose 0x" + Long.toHexString(handle) + " failed");
            return -1;
        }
    }

}
