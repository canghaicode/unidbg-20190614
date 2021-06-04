package cn.banny.unidbg.ios;

import cn.banny.unidbg.*;
import cn.banny.unidbg.arm.*;
import cn.banny.unidbg.arm.context.Arm32RegisterContext;
import cn.banny.unidbg.arm.context.Arm64RegisterContext;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.hook.HookListener;
import cn.banny.unidbg.ios.struct.DyldImageInfo;
import cn.banny.unidbg.memory.MemRegion;
import cn.banny.unidbg.memory.*;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.pointer.UnicornStructure;
import cn.banny.unidbg.spi.AbstractLoader;
import cn.banny.unidbg.spi.LibraryFile;
import cn.banny.unidbg.spi.Loader;
import cn.banny.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class MachOLoader extends AbstractLoader implements Memory, Loader, cn.banny.unidbg.ios.MachO {

    private static final Log log = LogFactory.getLog(MachOLoader.class);

    private boolean objcRuntime;

    MachOLoader(Emulator emulator, UnixSyscallHandler syscallHandler) {
        super(emulator, syscallHandler);

        // init stack
        long stackBase = STACK_BASE;
        if (emulator.getPointerSize() == 8) {
            stackBase += 0xf00000000L;
        }

        final long stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        unicorn.mem_map(stackBase - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        setStackPoint(stackBase);
        initializeTSD();
        this.setErrno(0);
    }

    @Override
    protected LibraryFile createLibraryFile(File file) {
        return new MachOLibraryFile(file);
    }

    public void setObjcRuntime(boolean objcRuntime) {
        this.objcRuntime = objcRuntime;
    }

    private UnicornPointer vars;
    private Pointer errno;

    private static final int __TSD_THREAD_SELF = 0;
    private static final int __TSD_ERRNO = 1;
    private static final int __TSD_MIG_REPLY = 2;
//    private static final int __PTK_FRAMEWORK_OBJC_KEY5 = 0x2d;

    private void initializeTSD() {
        final Pointer environ = allocateStack(emulator.getPointerSize() * 3);
        assert environ != null;
        final Pointer MallocCorruptionAbort = writeStackString("MallocCorruptionAbort=0");
        environ.setPointer(0, MallocCorruptionAbort);
        final Pointer MallocStackLogging = null;//writeStackString("MallocStackLogging=malloc"); // malloc, vm, all
        environ.setPointer(emulator.getPointerSize(), MallocStackLogging);
        environ.setPointer(emulator.getPointerSize() * 2, null);

        UnicornPointer _NSGetEnviron = allocateStack(emulator.getPointerSize());
        _NSGetEnviron.setPointer(0, environ);

        final Pointer programName = writeStackString(emulator.getProcessName());
        Pointer _NSGetProgname = allocateStack(emulator.getPointerSize());
        _NSGetProgname.setPointer(0, programName);

        Pointer _NSGetArgc = allocateStack(emulator.getPointerSize());
        _NSGetArgc.setInt(0, 1);

        Pointer args = allocateStack(emulator.getPointerSize());
        args.setPointer(0, programName);
        Pointer _NSGetArgv = allocateStack(emulator.getPointerSize());
        _NSGetArgv.setPointer(0, args);

        vars = allocateStack(emulator.getPointerSize() * 5);
        vars.setPointer(0, null); // _NSGetMachExecuteHeader
        vars.setPointer(emulator.getPointerSize(), _NSGetArgc);
        vars.setPointer(2 * emulator.getPointerSize(), _NSGetArgv);
        vars.setPointer(3 * emulator.getPointerSize(), _NSGetEnviron);
        vars.setPointer(4 * emulator.getPointerSize(), _NSGetProgname);

        errno = allocateStack(emulator.getPointerSize());

        final UnicornPointer thread = allocateStack(0x1000); // reserve space for pthread_internal_t

        /* 0xa4必须固定，否则初始化objc会失败 */
        final UnicornPointer tsd = (UnicornPointer) thread.share(emulator.getPointerSize() == 8 ? 0xe0 : 0xa4); // tsd size
        assert tsd != null;
        tsd.setPointer(__TSD_THREAD_SELF * emulator.getPointerSize(), thread);
        tsd.setPointer(__TSD_ERRNO * emulator.getPointerSize(), errno);
        tsd.setPointer(__TSD_MIG_REPLY * emulator.getPointerSize(), null);

        Pointer locale = allocateStack(emulator.getPointerSize());

        Pointer gap = allocateStack(emulator.getPointerSize());

        if (emulator.getPointerSize() == 4) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tsd.peer);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_TPIDRRO_EL0, tsd.peer);
        }
        log.debug("initializeTSD tsd=" + tsd + ", thread=" + thread + ", environ=" + environ + ", vars=" + vars + ", locale=" + locale + ", gap=" + gap + ", errno=" + errno);
    }

    @Override
    protected Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException {
        return loadInternal(libraryFile, forceCallInit, true);
    }

    private MachOModule loadInternal(LibraryFile libraryFile, boolean forceCallInit, boolean checkBootstrap) throws IOException {
        MachOModule module = loadInternalPhase(libraryFile, true, checkBootstrap);

        for (MachOModule export : modules.values()) {
            if (!export.lazyLoadNeededList.isEmpty()) {
                log.info("Export module resolve needed library failed: " + export.name + ", neededList=" + export.lazyLoadNeededList);
            }
        }
        for (MachOModule m : modules.values()) {
            bindIndirectSymbolPointers(m);
            setupLazyPointerHandler(m);
        }

        notifySingle(Dyld.dyld_image_state_bound, module);
        notifySingle(Dyld.dyld_image_state_dependents_initialized, module);

        if (callInitFunction || forceCallInit) {
            for (MachOModule m : modules.values()) {
                m.callInitFunction(emulator);
            }

            for (MachOModule m : modules.values()) {
                m.callRoutines(emulator);
            }
        }

        return module;
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, boolean loadNeeded, boolean checkBootstrap) throws IOException {
        ByteBuffer buffer = libraryFile.mapBuffer();
        return loadInternalPhase(libraryFile, buffer, loadNeeded, checkBootstrap);
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, ByteBuffer buffer, boolean loadNeeded, boolean checkBootstrap) throws IOException {
        MachO machO = new MachO(new ByteBufferKaitaiStream(buffer));
        MachO.MagicType magic = machO.magic();
        switch (magic) {
            case FAT_BE:
                Map<Long, MachO.FatArch> archMap = new HashMap<>();
                for (MachO.FatArch arch : machO.fatHeader().fatArchs()) {
                    if ((arch.cputype() == MachO.CpuType.ARM && emulator.getPointerSize() == 4) || (arch.cputype() == MachO.CpuType.ARM64 && emulator.getPointerSize() == 8)) {
                        archMap.put(arch.cpusubtype(), arch);
                    }
                }
                MachO.FatArch arch = archMap.get(CPU_SUBTYPE_ARM_V7); // 优先加载armv7
                if (arch == null) {
                    Iterator<MachO.FatArch> iterator = archMap.values().iterator();
                    if (iterator.hasNext()) {
                        arch = iterator.next();
                    }
                }
                if (arch != null) {
                    buffer.limit((int) (arch.offset() + arch.size()));
                    buffer.position((int) arch.offset());
                    log.debug("loadFatArch=" + arch.cputype() + ", cpuSubType=" + arch.cpusubtype());
                    return loadInternalPhase(libraryFile, buffer.slice(), loadNeeded, checkBootstrap);
                }
                throw new IllegalArgumentException("find arch failed");
            case MACHO_LE_X86: // ARM
                if (machO.header().cputype() != MachO.CpuType.ARM) {
                    throw new UnsupportedOperationException("cpuType=" + machO.header().cputype());
                }
                break;
            case MACHO_LE_X64:
                if (machO.header().cputype() != MachO.CpuType.ARM64) {
                    throw new UnsupportedOperationException("cpuType=" + machO.header().cputype());
                }
                break;
            default:
                throw new UnsupportedOperationException("magic=" + magic);
        }

        switch (machO.header().filetype()) {
            case DYLIB:
            case EXECUTE:
                break;
            default:
                throw new UnsupportedOperationException("fileType=" + machO.header().filetype());
        }

        final boolean isExecutable = machO.header().filetype() == MachO.FileType.EXECUTE;
        final boolean isPositionIndependent = (machO.header().flags() & MH_PIE) != 0;

        if (checkBootstrap && !isExecutable && executableModule == null) {
            URL url = getClass().getResource(objcRuntime ? "/ios/bootstrap_objc" : "/ios/bootstrap");
            Module bootstrap = loadInternal(new URLibraryFile(url, "unidbg_bootstrap", DarwinResolver.LIB_VERSION), false, false);
//            emulator.traceCode();
//            emulator.attach().addBreakPoint(null, 0x409a7f44);
//            emulator.attach().addBreakPoint(null, 0x40b95d06);
            bootstrap.callEntry(emulator);
//            emulator.attach().debug();
        }

        long start = System.currentTimeMillis();
        long size = 0;
        String dyId = libraryFile.getName();
        String dylibPath = libraryFile.getName();
        MachO.DyldInfoCommand dyldInfoCommand = null;
        boolean finalSegment = false;
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case DYLD_INFO:
                case DYLD_INFO_ONLY:
                    if (dyldInfoCommand != null) {
                        throw new IllegalStateException("dyldInfoCommand=" + dyldInfoCommand);
                    }
                    dyldInfoCommand = (MachO.DyldInfoCommand) command.body();
                    break;
                case SEGMENT: {
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    if ("__PAGEZERO".equals(segmentCommand.segname())) {
                        break;
                    }
                    if (segmentCommand.filesize() > segmentCommand.vmsize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment load command %s filesize is larger than vmsize", command.type()));
                    }
                    if (finalSegment) {
                        throw new IllegalStateException("finalSegment");
                    }
                    if (((segmentCommand.vmaddr() + segmentCommand.vmsize()) % emulator.getPageAlign()) != 0) {
                        finalSegment = true;
                    }
                    if (segmentCommand.vmaddr() % emulator.getPageAlign() != 0) {
                        throw new IllegalArgumentException("vmaddr not page aligned");
                    }

                    if (segmentCommand.vmsize() == 0) {
                        break;
                    }
                    if (segmentCommand.vmsize() < segmentCommand.filesize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment %s has vmsize < filesize", command.type()));
                    }
                    long vmsize = ARM.alignSize(segmentCommand.vmsize(), emulator.getPageAlign());
                    long high = segmentCommand.vmaddr() + vmsize;
                    if (size < high) {
                        size = high;
                    }
                    break;
                }
                case SEGMENT_64: {
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
                        break;
                    }
                    if (segmentCommand64.filesize() > segmentCommand64.vmsize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment load command %s filesize is larger than vmsize", command.type()));
                    }
                    if (finalSegment) {
                        throw new IllegalStateException("finalSegment");
                    }
                    if (((segmentCommand64.vmaddr() + segmentCommand64.vmsize()) % emulator.getPageAlign()) != 0) {
                        finalSegment = true;
                    }
                    if (segmentCommand64.vmaddr() % emulator.getPageAlign() != 0) {
                        throw new IllegalArgumentException("vmaddr not page aligned");
                    }

                    if (segmentCommand64.vmsize() == 0) {
                        break;
                    }
                    if (segmentCommand64.vmsize() < segmentCommand64.filesize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment %s has vmsize < filesize", command.type()));
                    }
                    long vmsize = ARM.alignSize(segmentCommand64.vmsize(), emulator.getPageAlign());
                    long high = segmentCommand64.vmaddr() + vmsize;
                    if (size < high) {
                        size = high;
                    }
                    break;
                }
                case ID_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    dylibPath = dylibCommand.name().replace("@rpath", libraryFile.getPath());
                    dyId = FilenameUtils.getName(dylibPath);
                    break;
                case LOAD_DYLIB:
                // case LOAD_WEAK_DYLIB:
                case REEXPORT_DYLIB:
                case LOAD_UPWARD_DYLIB:
                case SYMTAB:
                case DYSYMTAB:
                    break;
                case ENCRYPTION_INFO:
                case ENCRYPTION_INFO_64:
                    MachO.EncryptionInfoCommand encryptionInfoCommand = (MachO.EncryptionInfoCommand) command.body();
                    if (encryptionInfoCommand.cryptid() != 0) {
                        throw new UnsupportedOperationException("Encrypted file");
                    }
                    break;
                case UUID:
                case FUNCTION_STARTS:
                case DATA_IN_CODE:
                case CODE_SIGNATURE:
                case SOURCE_VERSION:
                case SEGMENT_SPLIT_INFO:
                case DYLIB_CODE_SIGN_DRS:
                case SUB_FRAMEWORK:
                case RPATH:
                case VERSION_MIN_IPHONEOS:
                case LOAD_DYLINKER:
                case MAIN:
                case ROUTINES:
                    break;
                default:
                    log.info("Not handle loadCommand=" + command.type() + ", dylibPath=" + dylibPath);
                    break;
            }
        }

        final long loadBase = isExecutable ? 0 : mmapBaseAddress;
        long machHeader = -1;
        if (isExecutable) {
            long end = loadBase + size;
            if (end >= mmapBaseAddress) {
                mmapBaseAddress = end;
            }
        } else {
            mmapBaseAddress = loadBase + size;
        }

        if (log.isDebugEnabled()) {
            log.debug("start map dyid=" + dyId + ", base=0x" + Long.toHexString(loadBase) + ", size=0x" + Long.toHexString(size));
        }

        final List<NeedLibrary> neededList = new ArrayList<>();
        final List<MemRegion> regions = new ArrayList<>(5);
        final List<MachO.DylibCommand> exportDylibs = new ArrayList<>();
        MachO.SymtabCommand symtabCommand = null;
        MachO.DysymtabCommand dysymtabCommand = null;
        MachO.EntryPointCommand entryPointCommand = null;
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT: {
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    long begin = loadBase + segmentCommand.vmaddr();
                    if ("__PAGEZERO".equals(segmentCommand.segname())) {
                        regions.add(new MemRegion(begin, begin + segmentCommand.vmsize(), 0, libraryFile, segmentCommand.vmaddr()));
                        break;
                    }

                    for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                        checkSection(dyId, segmentCommand.segname(), section.sectName());
                    }

                    if (segmentCommand.vmsize() == 0) {
                        regions.add(new MemRegion(begin, begin, 0, libraryFile, segmentCommand.vmaddr()));
                        break;
                    }
                    int prot = get_segment_protection(segmentCommand.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    if (machHeader == -1 && "__TEXT".equals(segmentCommand.segname())) {
                        machHeader = begin;
                    }
                    Alignment alignment = this.mem_map(begin, segmentCommand.vmsize(), prot, dyId);
                    write_mem((int) segmentCommand.fileoff(), (int) segmentCommand.filesize(), begin, buffer);

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand.vmaddr()));
                    break;
                }
                case SEGMENT_64: {
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    long begin = loadBase + segmentCommand64.vmaddr();
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
                        regions.add(new MemRegion(begin, begin + segmentCommand64.vmsize(), 0, libraryFile, segmentCommand64.vmaddr()));
                        break;
                    }

                    for (MachO.SegmentCommand64.Section64 section : segmentCommand64.sections()) {
                        checkSection(dyId, segmentCommand64.segname(), section.sectName());
                    }

                    if (segmentCommand64.vmsize() == 0) {
                        regions.add(new MemRegion(begin, begin, 0, libraryFile, segmentCommand64.vmaddr()));
                        break;
                    }
                    int prot = get_segment_protection(segmentCommand64.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    if (machHeader == -1 && "__TEXT".equals(segmentCommand64.segname())) {
                        machHeader = begin;
                    }
                    Alignment alignment = this.mem_map(begin, segmentCommand64.vmsize(), prot, dyId);
                    if (log.isDebugEnabled()) {
                        log.debug("mem_map address=0x" + Long.toHexString(alignment.address) + ", size=0x" + Long.toHexString(alignment.size));
                    }
                    write_mem((int) segmentCommand64.fileoff(), (int) segmentCommand64.filesize(), begin, buffer);

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand64.vmaddr()));
                    break;
                }
                case LOAD_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    neededList.add(new NeedLibrary(dylibCommand.name(), false));
                    break;
                case LOAD_UPWARD_DYLIB:
                    dylibCommand = (MachO.DylibCommand) command.body();
                    neededList.add(new NeedLibrary(dylibCommand.name(), true));
                    break;
                case SYMTAB:
                    symtabCommand = (MachO.SymtabCommand) command.body();
                    break;
                case DYSYMTAB:
                    dysymtabCommand = (MachO.DysymtabCommand) command.body();
                    break;
                case REEXPORT_DYLIB:
                    exportDylibs.add((MachO.DylibCommand) command.body());
                    break;
                case MAIN:
                    entryPointCommand = (MachO.EntryPointCommand) command.body();
                    break;
            }
        }
        Log log = LogFactory.getLog("cn.banny.unidbg.ios." + dyId);
        if (!log.isDebugEnabled()) {
            log = MachOLoader.log;
        }
        if (log.isDebugEnabled()) {
            log.debug("load dyId=" + dyId + ", base=0x" + Long.toHexString(loadBase) + ", dyldInfoCommand=" + dyldInfoCommand + ", loadNeeded=" + loadNeeded + ", regions=" + regions + ", isPositionIndependent=" + isPositionIndependent);
        }

        Map<String, MachOModule> exportModules = new LinkedHashMap<>();

        for (MachO.DylibCommand dylibCommand : exportDylibs) {
            String neededLibrary = dylibCommand.name();
            log.debug(dyId + " need export dependency " + neededLibrary);

            MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
            if (loaded != null) {
                loaded.addReferenceCount();
                exportModules.put(FilenameUtils.getBaseName(loaded.name), loaded);
                continue;
            }
            LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, neededLibrary);
            if (libraryResolver != null && neededLibraryFile == null) {
                neededLibraryFile = libraryResolver.resolveLibrary(emulator, neededLibrary);
            }
            if (neededLibraryFile != null) {
                MachOModule needed = loadInternalPhase(neededLibraryFile, false, false);
                needed.addReferenceCount();
                exportModules.put(FilenameUtils.getBaseName(needed.name), needed);
            } else {
                log.debug(dyId + " load export dependency " + neededLibrary + " failed");
            }
        }

        Map<String, MachOModule> neededLibraries = new LinkedHashMap<>();
        Map<String, Module> upwardLibraries = new LinkedHashMap<>();
        final List<NeedLibrary> lazyLoadNeededList;
        if (loadNeeded) {
            lazyLoadNeededList = Collections.emptyList();
            for (NeedLibrary library : neededList) {
                String neededLibrary = library.path;
                log.debug(dyId + " need dependency " + neededLibrary);

                MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
                if (loaded != null) {
                    loaded.addReferenceCount();
                    neededLibraries.put(FilenameUtils.getBaseName(loaded.name), loaded);
                    continue;
                }
                LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, neededLibrary);
                if (libraryResolver != null && neededLibraryFile == null) {
                    neededLibraryFile = libraryResolver.resolveLibrary(emulator, neededLibrary);
                }
                if (neededLibraryFile != null) {
                    MachOModule needed = loadInternalPhase(neededLibraryFile, loadNeeded, false);
                    needed.addReferenceCount();
                    if (library.upward) {
                        upwardLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                    } else {
                        neededLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                    }
                } else {
                    log.info(dyId + " load dependency " + neededLibrary + " failed");
                }
            }
        } else {
            lazyLoadNeededList = neededList;
        }

        if (log.isDebugEnabled()) {
            log.debug("load dyId=" + dyId + ", base=0x" + Long.toHexString(loadBase) + ", neededLibraries=" + neededLibraries + ", upwardLibraries=" + upwardLibraries);
        }

        final long loadSize = size;
        MachOModule module = new MachOModule(machO, dyId, loadBase, loadSize, new HashMap<String, Module>(neededLibraries), regions,
                symtabCommand, dysymtabCommand, buffer, lazyLoadNeededList, upwardLibraries, exportModules, dylibPath, emulator, dyldInfoCommand, null, null, vars, machHeader, isExecutable);
        modules.put(dyId, module);

        if (isExecutable) {
            setExecuteModule(module);
        }

        for (MachOModule export : modules.values()) {
            for (Iterator<NeedLibrary> iterator = export.lazyLoadNeededList.iterator(); iterator.hasNext(); ) {
                NeedLibrary library = iterator.next();
                String neededLibrary = library.path;

                String name = FilenameUtils.getName(neededLibrary);
                MachOModule loaded = modules.get(name);
                if (loaded != null) {
                    if (library.upward) {
                        export.upwardLibraries.put(name, loaded);
                    } else {
                        export.neededLibraries().put(name, loaded);
                    }
                    iterator.remove();
                }
            }
        }

        processRebase(log, module);

        if ("libsystem_malloc.dylib".equals(dyId)) {
            malloc = module.findSymbolByName("_malloc");
            free = module.findSymbolByName("_free");
        } else if ("Foundation".equals(dyId)) {
            Symbol _NSSetLogCStringFunction = module.findSymbolByName("__NSSetLogCStringFunction", false);
            if (_NSSetLogCStringFunction == null) {
                throw new IllegalStateException("__NSSetLogCStringFunction is null");
            } else {
                Svc svc = emulator.getPointerSize() == 4 ? new ArmHook() {
                    @Override
                    protected HookStatus hook(Emulator emulator) {
                        Arm32RegisterContext context = emulator.getContext();
                        Pointer message = context.getR0Pointer();
                        int length = context.getR1Int();
                        boolean withSysLogBanner = context.getR2Int() != 0;
                        __NSSetLogCStringFunction(message, length, withSysLogBanner);
                        return HookStatus.LR(emulator, 0);
                    }
                } : new Arm64Hook() {
                    @Override
                    protected HookStatus hook(Emulator emulator) {
                        Arm64RegisterContext context = emulator.getContext();
                        Pointer message = context.getXPointer(0);
                        int length = context.getXInt(1);
                        boolean withSysLogBanner = context.getXInt(2) != 0;
                        __NSSetLogCStringFunction(message, length, withSysLogBanner);
                        return HookStatus.LR(emulator, 0);
                    }
                };
                _NSSetLogCStringFunction.call(emulator, emulator.getSvcMemory().registerSvc(svc));
            }
        }

        if (entryPointCommand != null) {
            module.setEntryPoint(entryPointCommand.entryOff());
        }

        if (maxDylibName == null || dyId.length() > maxDylibName.length()) {
            maxDylibName = dyId;
        }
        if (loadSize > maxSizeOfDylib) {
            maxSizeOfDylib = loadSize;
        }

        log.debug("Load library " + dyId + " offset=" + (System.currentTimeMillis() - start) + "ms");
        if (moduleListener != null) {
            moduleListener.onLoaded(emulator, module);
        }

        return module;
    }

    private void __NSSetLogCStringFunction(Pointer message, int length, boolean withSysLogBanner) {
        byte[] data = message.getByteArray(0, length);
        String str = new String(data, StandardCharsets.UTF_8);
        if (withSysLogBanner) {
            System.err.println("NSLog: " + str);
        } else {
            System.out.println("NSLog: " + str);
        }
    }

    private void checkSection(String dyId, String segName, String sectName) {
        // __OBJC need fNotifyObjC = true
        switch (sectName) {
            case "__text":
            case "__mod_init_func":
            case "__cstring":
            case "__cfstring":
            case "__nl_symbol_ptr":
            case "__la_symbol_ptr":
            case "__picsymbolstub4":
            case "__stub_helper":
            case "__const":
            case "__data":
            case "__bss":
            case "__common":
            case "__gcc_except_tab":
            case "__constrw":
            case "__dyld":
            case "__dof_magmalloc":
            case "__dof_plockstat":
            case "__dof_objc_runt":
            case "__symbolstub1":
            case "__symbol_stub4":
            case "__lazy_symbol":
            case "__ustring":
            case "__cfstring_CFN":
            case "__csbitmaps":
            case "__properties":
            case "__dof_NSXPCList":
            case "__dof_Cocoa_Lay":
            case "__dof_NSXPCProx":
            case "__dof_NSProgres":
            case "__dof_NSXPCConn":
            case "__cf_except_bt":
            case "__dof_CFRunLoop":
            case "__dof_Cocoa_Aut":
            case "__dof_cache":
                break;
            case "__stubs":
            case "__unwind_info":
            case "__got":
            case "__eh_frame":
                break;
            default:
                boolean isObjc = sectName.startsWith("__objc_");
                if (isObjc) {
                    log.debug("checkSection name=" + sectName + ", dyId=" + dyId + ", segName=" + segName);
                } else {
                    log.info("checkSection name=" + sectName + ", dyId=" + dyId + ", segName=" + segName);
                }
                break;
        }
    }

    private void processRebase(Log log, MachOModule module) {
        MachO.DyldInfoCommand dyldInfoCommand = module.dyldInfoCommand;
        if (dyldInfoCommand == null) {
            return;
        }

        if (dyldInfoCommand.rebaseSize() > 0) {
            ByteBuffer buffer = module.buffer.duplicate();
            buffer.limit((int) (dyldInfoCommand.rebaseOff() + dyldInfoCommand.rebaseSize()));
            buffer.position((int) dyldInfoCommand.rebaseOff());
            rebase(log, buffer.slice(), module);
        }
    }

    private void rebase(Log log, ByteBuffer buffer, MachOModule module) {
        final List<MemRegion> regions = module.getRegions();
        int type = 0;
        int segmentIndex;
        long address = module.base;
        long segmentEndAddress = module.base + module.size;
        int count;
        int skip;
        boolean done = false;
        while (!done && buffer.hasRemaining()) {
            int b = buffer.get() & 0xff;
            int immediate = b & REBASE_IMMEDIATE_MASK;
            int opcode = b & REBASE_OPCODE_MASK;
            switch (opcode) {
                case REBASE_OPCODE_DONE:
                    done = true;
                    break;
                case REBASE_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    break;
                case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    segmentIndex = immediate;
                    if (segmentIndex >= regions.size()) {
                        throw new IllegalStateException(String.format("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (0..%d)", segmentIndex, regions.size() - 1));
                    }
                    MemRegion region = regions.get(segmentIndex);
                    address = region.begin + Utils.readULEB128(buffer).longValue();
                    segmentEndAddress = region.end;
                    break;
                case REBASE_OPCODE_ADD_ADDR_ULEB:
                    address += Utils.readULEB128(buffer).longValue();
                    break;
                case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                    address += (immediate * emulator.getPointerSize());
                    break;
                case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                    for (int i = 0; i < immediate; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        rebaseAt(log, type, address, module);
                        address += emulator.getPointerSize();
                    }
                    break;
                case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                    count = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        rebaseAt(log, type, address, module);
                        address += emulator.getPointerSize();
                    }
                    break;
                case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    rebaseAt(log, type, address, module);
                    address += (Utils.readULEB128(buffer).longValue() + emulator.getPointerSize());
                    break;
                case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                    count = Utils.readULEB128(buffer).intValue();
                    skip = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        rebaseAt(log, type, address, module);
                        address += (skip + emulator.getPointerSize());
                    }
                    break;
                default:
                    throw new IllegalStateException("bad rebase opcode=0x" + Integer.toHexString(opcode));
            }
        }
    }

    private void rebaseAt(Log log, int type, long address, Module module) {
        Pointer pointer = UnicornPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }
        Pointer newPointer = pointer.getPointer(0);
        Pointer old = newPointer;
        if (newPointer == null) {
            newPointer = UnicornPointer.pointer(emulator, module.base);
        } else {
            newPointer = newPointer.share(module.base);
        }
        /*if (log.isDebugEnabled()) {
            log.debug("rebaseAt type=" + type + ", address=0x" + Long.toHexString(address - module.base) + ", module=" + module.name + ", old=" + old + ", new=" + newPointer);
        }*/
        switch (type) {
            case REBASE_TYPE_POINTER:
            case REBASE_TYPE_TEXT_ABSOLUTE32:
                pointer.setPointer(0, newPointer);
                break;
            default:
                throw new IllegalStateException("bad rebase type " + type);
        }
    }

    private void bindLocalRelocations(MachOModule module) {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand.nLocRel() <= 0) {
            return;
        }

        ByteBuffer buffer = module.buffer;
        buffer.limit((int) (dysymtabCommand.locRelOff() + dysymtabCommand.nLocRel() * 8));
        buffer.position((int) dysymtabCommand.locRelOff());
        ByteBuffer slice = buffer.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);

        Log log = LogFactory.getLog("cn.banny.unidbg.ios." + module.name);

        for (int i = 0; i < dysymtabCommand.nLocRel(); i++) {
            Relocation relocation = Relocation.create(slice);
            if (relocation.pcRel || relocation.extern || relocation.scattered ||
                    relocation.length != (emulator.getPointerSize() == 8 ? 3 : 2) ||
                    relocation.type != ARM_RELOC_VANILLA) {
                throw new IllegalStateException("Unexpected relocation found.");
            }

            buffer.limit(relocation.address + emulator.getPointerSize());
            buffer.position(relocation.address);
            long target = emulator.getPointerSize() == 8 ? buffer.getLong() : buffer.getInt();
            Pointer pointer = UnicornPointer.pointer(emulator, module.base + relocation.address);
            if (pointer == null) {
                throw new IllegalStateException();
            }
            pointer.setPointer(0, UnicornPointer.pointer(emulator, module.base + target));
            if (log.isDebugEnabled()) {
                log.debug("bindLocalRelocations address=0x" + Integer.toHexString(relocation.address) + ", symbolNum=0x" + Integer.toHexString(relocation.symbolNum) + ", target=0x" + Long.toHexString(target));
            }
        }
    }

    private boolean bindExternalRelocations(MachOModule module) throws IOException {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand.nExtRel() <= 0) {
            return true;
        }

        ByteBuffer buffer = module.buffer;
        buffer.limit((int) (dysymtabCommand.extRelOff() + dysymtabCommand.nExtRel() * 8));
        buffer.position((int) dysymtabCommand.extRelOff());
        ByteBuffer slice = buffer.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);

        Log log = LogFactory.getLog("cn.banny.unidbg.ios." + module.name);

        boolean ret = true;
        for (int i = 0; i < dysymtabCommand.nExtRel(); i++) {
            Relocation relocation = Relocation.create(slice);
            if (relocation.pcRel || !relocation.extern || relocation.scattered ||
                    relocation.length != (emulator.getPointerSize() == 8 ? 3 : 2) ||
                    relocation.type != ARM_RELOC_VANILLA) {
                throw new IllegalStateException("Unexpected relocation found.");
            }

            MachOSymbol symbol = module.getSymbolByIndex(relocation.symbolNum);
            Pointer pointer = UnicornPointer.pointer(emulator, module.base + relocation.address);
            if (pointer == null) {
                throw new IllegalStateException();
            }

            boolean isWeakRef = (symbol.nlist.desc() & N_WEAK_REF) != 0;
            long address = resolveSymbol(module, symbol);

            if (address == 0L) {
                log.warn("bindExternalRelocations failed symbol=" + symbol + ", isWeakRef=" + isWeakRef);
                ret = false;
            } else {
                pointer.setPointer(0, UnicornPointer.pointer(emulator, address));
                log.debug("bindExternalRelocations address=0x" + Long.toHexString(relocation.address) + ", symbolNum=0x" + Integer.toHexString(relocation.symbolNum) + ", symbolName=" + symbol.getName());
            }
        }
        return ret;
    }

    private long resolveSymbol(Module module, Symbol symbol) throws IOException {
        Symbol replace = module.findSymbolByName(symbol.getName(), true);
        long address = replace == null ? 0L : replace.getAddress();
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), replace == null ? module.name : replace.getModuleName(), symbol.getName(), address);
            if (hook > 0) {
                address = hook;
                break;
            }
        }
        return address;
    }

    private Pointer dyldLazyBinder;
    private Pointer dyldFuncLookup;

    private void setupLazyPointerHandler(MachOModule module) {
        if (module.lazyPointerProcessed) {
            return;
        }
        module.lazyPointerProcessed = true;

        for (MachO.LoadCommand command : module.machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    if ("__DATA".equals(segmentCommand.segname())) {
                        for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                            if ("__dyld".equals(section.sectName())) {
                                Pointer dd = UnicornPointer.pointer(emulator, module.base + section.addr());
                                if (dyldLazyBinder == null) {
                                    dyldLazyBinder = emulator.getSvcMemory().registerSvc(new ArmSvc() {
                                        @Override
                                        public long handle(Emulator emulator) {
                                            return ((Dyld) emulator.getDlfcn())._stub_binding_helper();
                                        }
                                    });
                                }
                                if (dyldFuncLookup == null) {
                                    dyldFuncLookup = emulator.getSvcMemory().registerSvc(new ArmSvc() {
                                        @Override
                                        public long handle(Emulator emulator) {
                                            String name = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0).getString(0);
                                            Pointer address = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                                            return ((Dyld) emulator.getDlfcn())._dyld_func_lookup(emulator, name, address);
                                        }
                                    });
                                }
                                if (dd != null) {
                                    dd.setPointer(0, dyldLazyBinder);
                                    dd.setPointer(emulator.getPointerSize(), dyldFuncLookup);
                                }
                            }
                        }
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if ("__DATA".equals(segmentCommand64.segname())) {
                        for (MachO.SegmentCommand64.Section64 section : segmentCommand64.sections()) {
                            if ("__dyld".equals(section.sectName())) {
                                Pointer dd = UnicornPointer.pointer(emulator, module.base + section.addr());
                                if (dyldLazyBinder == null) {
                                    dyldLazyBinder = emulator.getSvcMemory().registerSvc(new Arm64Svc() {
                                        @Override
                                        public long handle(Emulator emulator) {
                                            return ((Dyld) emulator.getDlfcn())._stub_binding_helper();
                                        }
                                    });
                                }
                                if (dyldFuncLookup == null) {
                                    dyldFuncLookup = emulator.getSvcMemory().registerSvc(new Arm64Svc() {
                                        @Override
                                        public long handle(Emulator emulator) {
                                            String name = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0).getString(0);
                                            Pointer address = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                                            return ((Dyld) emulator.getDlfcn())._dyld_func_lookup(emulator, name, address);
                                        }
                                    });
                                }
                                if (dd != null) {
                                    dd.setPointer(0, dyldLazyBinder);
                                    dd.setPointer(emulator.getPointerSize(), dyldFuncLookup);
                                }
                            }
                        }
                    }
                    break;
            }
        }
    }

    private void bindIndirectSymbolPointers(MachOModule module) throws IOException {
        if (module.indirectSymbolBound) {
            return;
        }
        module.indirectSymbolBound = true;

        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        List<Long> indirectTable = dysymtabCommand.indirectSymbols();
        Log log = LogFactory.getLog("cn.banny.unidbg.ios." + module.name);
        if (!log.isDebugEnabled()) {
            log = MachOLoader.log;
        }

        MachO.DyldInfoCommand dyldInfoCommand = module.dyldInfoCommand;
        if (dyldInfoCommand == null) {
            bindLocalRelocations(module);

            boolean ret = true;
            for (MachO.LoadCommand command : module.machO.loadCommands()) {
                switch (command.type()) {
                    case SEGMENT:
                        MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                        for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                            long type = section.flags() & SECTION_TYPE;
                            long elementCount = section.size() / emulator.getPointerSize();

                            if (type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) {
                                continue;
                            }

                            long ptrToBind = section.addr();
                            int indirectTableOffset = (int) section.reserved1();
                            for (int i = 0; i < elementCount; i++, ptrToBind += emulator.getPointerSize()) {
                                long symbolIndex = indirectTable.get(indirectTableOffset + i);
                                if (symbolIndex == INDIRECT_SYMBOL_ABS) {
                                    continue; // do nothing since already has absolute address
                                }
                                if (symbolIndex == INDIRECT_SYMBOL_LOCAL) {
                                    UnicornPointer pointer = UnicornPointer.pointer(emulator, ptrToBind + module.base);
                                    if (pointer == null) {
                                        throw new IllegalStateException("pointer=" + pointer);
                                    }
                                    Pointer newPointer = pointer.getPointer(0);
                                    if (newPointer == null) {
                                        newPointer = UnicornPointer.pointer(emulator, module.base);
                                    } else {
                                        newPointer = newPointer.share(module.base);
                                    }
                                    if (log.isDebugEnabled()) {
                                        log.debug("bindIndirectSymbolPointers pointer=" + pointer + ", newPointer=" + newPointer);
                                    }
                                    pointer.setPointer(0, newPointer);
                                    continue;
                                }

                                MachOSymbol symbol = module.getSymbolByIndex((int) symbolIndex);
                                if (symbol == null) {
                                    log.warn("bindIndirectSymbolPointers symbol is null");
                                    ret = false;
                                    continue;
                                }

                                boolean isWeakRef = (symbol.nlist.desc() & N_WEAK_REF) != 0;
                                long address = resolveSymbol(module, symbol);

                                UnicornPointer pointer = UnicornPointer.pointer(emulator, ptrToBind + module.base);
                                if (pointer == null) {
                                    throw new IllegalStateException("pointer=" + pointer);
                                }
                                if (address == 0L) {
                                    if (isWeakRef) {
                                        log.info("bindIndirectSymbolPointers symbol=" + symbol + ", isWeakRef=" + isWeakRef);
                                        pointer.setPointer(0, null);
                                    } else {
                                        log.warn("bindIndirectSymbolPointers failed symbol=" + symbol);
                                    }
                                } else {
                                    pointer.setPointer(0, UnicornPointer.pointer(emulator, address));
                                    if (log.isDebugEnabled()) {
                                        log.debug("bindIndirectSymbolPointers symbolIndex=0x" + Long.toHexString(symbolIndex) + ", symbol=" + symbol + ", ptrToBind=0x" + Long.toHexString(ptrToBind));
                                    }
                                }
                            }
                        }
                        break;
                    case SEGMENT_64:
                        throw new UnsupportedOperationException("bindIndirectSymbolPointers SEGMENT_64");
                }
            }

            ret &= bindExternalRelocations(module);
            module.allSymbolBond = ret;
        } else {
            if (dyldInfoCommand.bindSize() > 0) {
                ByteBuffer buffer = module.buffer.duplicate();
                buffer.limit((int) (dyldInfoCommand.bindOff() + dyldInfoCommand.bindSize()));
                buffer.position((int) dyldInfoCommand.bindOff());
                module.allSymbolBond = eachBind(log, buffer.slice(), module, false);
            }
            if (dyldInfoCommand.lazyBindSize() > 0) {
                ByteBuffer buffer = module.buffer.duplicate();
                buffer.limit((int) (dyldInfoCommand.lazyBindOff() + dyldInfoCommand.lazyBindSize()));
                buffer.position((int) dyldInfoCommand.lazyBindOff());
                module.allLazySymbolBond = eachBind(log, buffer.slice(), module, true);
            }
        }
    }

    private boolean eachBind(Log log, ByteBuffer buffer, MachOModule module, boolean lazy) throws IOException {
        final List<MemRegion> regions = module.getRegions();
        int type = lazy ? BIND_TYPE_POINTER : 0;
        int segmentIndex;
        long address = module.base;
        long segmentEndAddress = address + module.size;
        String symbolName = null;
        int symbolFlags = 0;
        long libraryOrdinal = 0;
        long addend = 0;
        int count;
        int skip;
        boolean done = false;
        boolean ret = true;
        while (!done && buffer.hasRemaining()) {
            int b = buffer.get() & 0xff;
            int immediate = b & BIND_IMMEDIATE_MASK;
            int opcode = b & BIND_OPCODE_MASK;
            switch (opcode) {
                case BIND_OPCODE_DONE:
                    if (!lazy) {
                        done = true;
                    }
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                    libraryOrdinal = immediate;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                    libraryOrdinal = Utils.readULEB128(buffer).intValue();
                    break;
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                    // the special ordinals are negative numbers
                    if ( immediate == 0 )
                        libraryOrdinal = 0;
                    else {
                        libraryOrdinal = BIND_OPCODE_MASK | immediate;
                    }
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    while ((b = buffer.get()) != 0) {
                        baos.write(b);
                    }
                    symbolName = baos.toString();
                    symbolFlags = immediate;
                    break;
                case BIND_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    break;
                case BIND_OPCODE_SET_ADDEND_SLEB:
                    addend = Utils.readULEB128(buffer).longValue();
                    break;
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    segmentIndex = immediate;
                    if (segmentIndex >= regions.size()) {
                        throw new IllegalStateException(String.format("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (0..%d)", segmentIndex, regions.size() - 1));
                    }
                    MemRegion region = regions.get(segmentIndex);
                    address = region.begin + Utils.readULEB128(buffer).longValue();
                    segmentEndAddress = region.end;
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB:
                    address += Utils.readULEB128(buffer).longValue();
                    break;
                case BIND_OPCODE_DO_BIND:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    ret &= doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                    address += emulator.getPointerSize();
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    ret &= doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                    address += (Utils.readULEB128(buffer).longValue() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    ret &= doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                    address += (immediate*emulator.getPointerSize() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    count = Utils.readULEB128(buffer).intValue();
                    skip = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        ret &= doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                        address += (skip + emulator.getPointerSize());
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("bad bind opcode 0x%s in bind info", Integer.toHexString(opcode)));
            }
        }
        return ret;
    }

    private boolean doBindAt(Log log, long libraryOrdinal, int type, long address, String symbolName, int symbolFlags, long addend, MachOModule module, boolean lazy) throws IOException {
        Symbol symbol = module.findSymbolByName(symbolName, true);
        if (symbol == null) {
            log.warn("doBindAt type=" + type + ", symbolName=" + symbolName + ", address=0x" + Long.toHexString(address - module.base) + ", lazy=" + lazy + ", upwardLibraries=" + module.upwardLibraries + ", libraryOrdinal=" + libraryOrdinal);
            return false;
        }
        Pointer pointer = UnicornPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }

        long bindAt = symbol.getAddress();
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), symbol.getModuleName(), symbol.getName(), bindAt);
            if (hook > 0) {
                bindAt = hook;
                break;
            }
        }

        /*if (log.isDebugEnabled()) {
            log.debug("doBindAt 0x=" + Long.toHexString(symbol.getValue()) + ", type=" + type + ", symbolName=" + symbolName + ", symbolFlags=" + symbolFlags + ", addend=" + addend + ", address=0x" + Long.toHexString(address - module.base) + ", lazy=" + lazy + ", symbol=" + symbol + ", libName=" + module.name);
        }*/

        Pointer newPointer = UnicornPointer.pointer(emulator, bindAt);
        if (newPointer == null) {
            newPointer = UnicornPointer.pointer(emulator, addend);
        } else {
            newPointer = newPointer.share(addend);
        }
        switch (type) {
            case BIND_TYPE_POINTER:
                pointer.setPointer(0, newPointer);
                break;
            case BIND_TYPE_TEXT_ABSOLUTE32:
                pointer.setInt(0, (int) (symbol.getAddress() + addend));
                break;
            default:
                throw new IllegalStateException("bad bind type " + type);
        }
        return true;
    }

    private String maxDylibName;
    private long maxSizeOfDylib;

    private void write_mem(int offset, int size, long begin, ByteBuffer buffer) {
        if (size > 0) {
            buffer.limit(offset + size);
            buffer.position(offset);
            byte[] data = new byte[size];
            buffer.get(data);
            unicorn.mem_write(begin, data);
        }
    }

    private final Map<String, MachOModule> modules = new LinkedHashMap<>();

    private int get_segment_protection(MachO.VmProt vmProt) {
        int prot = Unicorn.UC_PROT_NONE;
        if (vmProt.read()) prot |= Unicorn.UC_PROT_READ;
        if (vmProt.write()) prot |= Unicorn.UC_PROT_WRITE;
        if (vmProt.execute()) prot |= Unicorn.UC_PROT_EXEC;
        return prot;
    }

    @Override
    public int brk(long address) {
        throw new UnsupportedOperationException();
    }

    private Symbol malloc, free;

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        if (runtime) {
            return MemoryBlockImpl.alloc(this, length);
        } else {
            return MemoryAllocBlock.malloc(emulator, malloc, free, length);
        }
    }

    @Override
    public void setErrno(int errno) {
        this.errno.setInt(0, errno);
    }

    @Override
    public File dumpHeap() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] unpack(File elfFile) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String path) throws IOException {
        return dlopen(path, true);
    }

    @Override
    public Module dlopen(String path, boolean callInit) throws IOException {
        MachOModule loaded = modules.get(FilenameUtils.getName(path));
        if (loaded != null) {
            loaded.addReferenceCount();
            return loaded;
        }

        for (Module module : getLoadedModules()) {
            for (cn.banny.unidbg.memory.MemRegion memRegion : module.getRegions()) {
                if (path.equals(memRegion.getName())) {
                    module.addReferenceCount();
                    return module;
                }
            }
        }

        LibraryFile libraryFile = libraryResolver == null ? null : libraryResolver.resolveLibrary(emulator, path);
        if (libraryFile == null) {
            return null;
        }

        MachOModule module = loadInternalPhase(libraryFile, true, true);

        for (MachOModule export : modules.values()) {
            if (!export.lazyLoadNeededList.isEmpty()) {
                log.info("Export module resolve needed library failed: " + export.name + ", neededList=" + export.lazyLoadNeededList);
            }
        }
        for (MachOModule m : modules.values()) {
            bindIndirectSymbolPointers(m);
            setupLazyPointerHandler(m);
        }

        if (!callInitFunction) { // No need call init array
            for (MachOModule m : modules.values()) {
                m.initFunctionList.clear();
            }
        }

        if (callInit) {
            for (MachOModule m : modules.values()) {
                m.callInitFunction(emulator);
            }

            for (MachOModule m : modules.values()) {
                m.callRoutines(emulator);
            }
        }

        module.addReferenceCount();
        return module;
    }

    @Override
    public boolean dlclose(long handle) {
        throw new UnsupportedOperationException();
    }


    @Override
    public Symbol dlsym(long handle, String symbolName) throws IOException {
        for (Module module : modules.values()) {
            MachOModule mm = (MachOModule) module;
            if (mm.machHeader == handle) {
                return module.findSymbolByName(symbolName, false);
            }
        }
        if (handle == RTLD_DEFAULT) {
            for (Module module : modules.values()) {
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        log.warn("dlsym failed: handle=" + handle + ", symbolName=" + symbolName);
        return null;
    }

    @Override
    public Collection<Module> getLoadedModules() {
        return new ArrayList<Module>(modules.values());
    }

    @Override
    public String getMaxLengthLibraryName() {
        return maxDylibName;
    }

    @Override
    public long getMaxSizeOfLibrary() {
        return maxSizeOfDylib;
    }

    @Override
    public void runThread(int threadId, long timeout) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void runLastThread(long timeout) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean hasThread(int threadId) {
        throw new UnsupportedOperationException();
    }

    final List<UnicornPointer> addImageCallbacks = new ArrayList<>();
    final List<UnicornPointer> boundHandlers = new ArrayList<>();
    final List<UnicornPointer> initializedHandlers = new ArrayList<>();

    private void notifySingle(int state, MachOModule module) {
        int elementSize = UnicornStructure.calculateSize(DyldImageInfo.class);
        Pointer pointer = emulator.getSvcMemory().allocate(elementSize, "notifySingle");
        DyldImageInfo info = new DyldImageInfo(pointer);
        info.imageFilePath = module.createPathMemory(emulator.getSvcMemory());
        info.imageLoadAddress = UnicornPointer.pointer(emulator, module.machHeader);
        info.imageFileModDate = 0;
        info.pack();
        switch (state) {
            case Dyld.dyld_image_state_bound:
                long slide = Dyld.computeSlide(emulator, module.machHeader);
                if (!module.executable) {
                    for (UnicornPointer callback : addImageCallbacks) {
                        if (log.isDebugEnabled()) {
                            log.debug("notifySingle callback=" + callback);
                        }
                        if (module.addImageCallSet.add(callback)) {
                            MachOModule.emulateFunction(emulator, callback.peer, (int) module.machHeader, slide);
                        }
                    }
                }
                for (UnicornPointer handler : boundHandlers) {
                    if (log.isDebugEnabled()) {
                        log.debug("notifySingle state=" + state + ", handler=" + handler);
                    }
                    if (module.boundCallSet.add(handler)) {
                        MachOModule.emulateFunction(emulator, handler.peer, state, 1, pointer);
                    }
                }
                break;
            case Dyld.dyld_image_state_dependents_initialized:
                for (UnicornPointer handler : initializedHandlers) {
                    if (log.isDebugEnabled()) {
                        log.debug("notifySingle state=" + state + ", handler=" + handler);
                    }
                    if (module.initializedCallSet.add(handler)) {
                        MachOModule.emulateFunction(emulator, handler.peer, state, 1, pointer);
                    }
                }
                break;
            default:
                throw new UnsupportedOperationException("state=" + state);
        }
    }

    private void setExecuteModule(MachOModule module) {
        if (executableModule == null) {
            executableModule = module;

            vars.setPointer(0, UnicornPointer.pointer(emulator, module.machHeader)); // _NSGetMachExecuteHeader
        }
    }

    private MachOModule executableModule;

    final long allocate(long size, long mask) {
        if (log.isDebugEnabled()) {
            log.debug("allocate size=0x" + Long.toHexString(size) + ", mask=0x" + Long.toHexString(mask));
        }

        long address = allocateMapAddress(mask, size);
        int prot = UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE;
        unicorn.mem_map(address, size,prot );
        memoryMap.put(address, new MemoryMap(address, size, prot));
        return address;
    }

    public Module getExecutableModule() {
        return executableModule;
    }

    @Override
    public long mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());

        if (((flags & cn.banny.unidbg.ios.MachO.MAP_ANONYMOUS) != 0) || (start == 0 && fd <= 0 && offset == 0)) {
            long addr = allocateMapAddress(0, aligned);
            log.debug("mmap2 addr=0x" + Long.toHexString(addr) + ", mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress) + ", start=" + start + ", fd=" + fd + ", offset=" + offset + ", aligned=" + aligned);
            unicorn.mem_map(addr, aligned, prot);
            memoryMap.put(addr, new MemoryMap(addr, aligned, prot));
            return addr;
        }
        try {
            FileIO file;
            if (start == 0 && fd > 0 && (file = syscallHandler.fdMap.get(fd)) != null) {
                long addr = allocateMapAddress(0, aligned);
                log.debug("mmap2 addr=0x" + Long.toHexString(addr) + ", mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress));
                return file.mmap2(unicorn, addr, aligned, prot, offset, length, memoryMap);
            }

            if ((flags & MAP_FIXED) != 0) {
                if (log.isDebugEnabled()) {
                    log.debug("mmap2 MAP_FIXED start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=" + prot + ", fd=" + fd + ", offset=0x" + Long.toHexString(offset));
                }

                MemoryMap mapped = null;
                for (MemoryMap map : memoryMap.values()) {
                    if (start >= map.base && start + aligned < map.base + map.size) {
                        mapped = map;
                    }
                }

                if (mapped != null) {
                    unicorn.mem_unmap(start, aligned);
                }
                FileIO io = syscallHandler.fdMap.get(fd);
                if (io != null) {
                    return io.mmap2(unicorn, start, aligned, prot, offset, length, memoryMap);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        throw new AbstractMethodError("mmap2 start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset);
    }

    @Override
    protected long getModuleBase(Module module) {
        return ((MachOModule) module).machHeader;
    }
}
