package cn.banny.unidbg.ios;

import cn.banny.unidbg.arm.AbstractARM64Emulator;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.Dlfcn;
import cn.banny.unidbg.spi.LibraryFile;
import cn.banny.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.UnicornConst;

import java.io.File;
import java.net.URL;
import java.nio.ByteBuffer;

public class DarwinARM64Emulator extends AbstractARM64Emulator {

    public DarwinARM64Emulator() {
        this(null);
    }

    public DarwinARM64Emulator(String processName) {
        super(processName);

        setupTraps();
    }

    private void setupTraps() {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            unicorn.mem_map(LR, 0x10000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
            KeystoneEncoded encoded = keystone.assemble("b #0");
            byte[] b0 = encoded.getMachineCode();
            ByteBuffer buffer = ByteBuffer.allocate(0x10000);
            for (int i = 0; i < 0x10000; i += b0.length) {
                buffer.put(b0);
            }
            unicorn.mem_write(LR, buffer.array());
        }

        long _COMM_PAGE_MEMORY_SIZE = (MachO._COMM_PAGE64_BASE_ADDRESS+0x038);	// uint64_t max memory size */
        Pointer commPageMemorySize = UnicornPointer.pointer(this, _COMM_PAGE_MEMORY_SIZE);
        if (commPageMemorySize != null) {
            commPageMemorySize.setLong(0, 0);
        }

        long _COMM_PAGE_NCPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x022);	// uint8_t number of configured CPUs
        Pointer commPageNCpus = UnicornPointer.pointer(this, _COMM_PAGE_NCPUS);
        if (commPageNCpus != null) {
            commPageNCpus.setByte(0, (byte) 1);
        }

        long _COMM_PAGE_ACTIVE_CPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x034);	// uint8_t number of active CPUs (hw.activecpu)
        Pointer commPageActiveCpus = UnicornPointer.pointer(this, _COMM_PAGE_ACTIVE_CPUS);
        if (commPageActiveCpus != null) {
            commPageActiveCpus.setByte(0, (byte) 1);
        }

        long _COMM_PAGE_PHYSICAL_CPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x035);	// uint8_t number of physical CPUs (hw.physicalcpu_max)
        Pointer commPagePhysicalCpus = UnicornPointer.pointer(this, _COMM_PAGE_PHYSICAL_CPUS);
        if (commPagePhysicalCpus != null) {
            commPagePhysicalCpus.setByte(0, (byte) 1);
        }

        long _COMM_PAGE_LOGICAL_CPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x036);	// uint8_t number of logical CPUs (hw.logicalcpu_max)
        Pointer commPageLogicalCpus = UnicornPointer.pointer(this, _COMM_PAGE_LOGICAL_CPUS);
        if (commPageLogicalCpus != null) {
            commPageLogicalCpus.setByte(0, (byte) 1);
        }
    }

    @Override
    protected Memory createMemory(UnixSyscallHandler syscallHandler) {
        return new MachOLoader(this, syscallHandler);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new Dyld64((MachOLoader) memory, svcMemory);
    }

    @Override
    protected UnixSyscallHandler createSyscallHandler(SvcMemory svcMemory) {
        return new ARM64SyscallHandler(svcMemory);
    }

    @Override
    public VM createDalvikVM(File apkFile) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getLibraryExtension() {
        return ".dylib";
    }

    @Override
    public String getLibraryPath() {
        return "/ios/lib/";
    }

    @Override
    public LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, null);
    }

    @Override
    public int getPageAlign() {
        return 0x4000;
    }
}
