package cn.banny.unidbg.ios;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.StopEmulatorException;
import cn.banny.unidbg.Svc;
import cn.banny.unidbg.arm.ARM;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.Cpsr;
import cn.banny.unidbg.arm.context.Arm64RegisterContext;
import cn.banny.unidbg.arm.context.EditableArm64RegisterContext;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.ios.file.LocalDarwinUdpSocket;
import cn.banny.unidbg.ios.struct.kernel.*;
import cn.banny.unidbg.memory.MemoryMap;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.SyscallHandler;
import cn.banny.unidbg.unix.UnixEmulator;
import cn.banny.unidbg.unix.UnixSyscallHandler;
import cn.banny.unidbg.unix.file.SocketIO;
import cn.banny.unidbg.unix.file.TcpSocket;
import cn.banny.unidbg.unix.file.UdpSocket;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.*;

/**
 * http://androidxref.com/4.4.4_r1/xref/external/kernel-headers/original/asm-arm/unistd.h
 */
public class ARM64SyscallHandler extends UnixSyscallHandler implements SyscallHandler, DarwinSyscall {

    private static final Log log = LogFactory.getLog(ARM64SyscallHandler.class);

    private final SvcMemory svcMemory;

    ARM64SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @Override
    public void hook(Unicorn u, int intno, Object user) {
        Emulator emulator = (Emulator) user;
        UnicornPointer pc = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);

        if (intno == ARMEmulator.EXCP_BKPT) { // brk
            emulator.attach().brk(pc, (pc.getInt(0) >> 5) & 0xffff);
            return;
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new UnicornException("intno=" + intno);
        }

        final int svcNumber = (pc.getInt(-4) >> 5) & 0xffff;

        int NR = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X16)).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (svcNumber != DARWIN_SWI_SYSCALL) {
                Svc svc = svcMemory.getSvc(svcNumber);
                if (svc != null) {
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, svc.handle(emulator));
                    return;
                }
                u.emu_stop();
                throw new UnicornException("svc number: " + svcNumber + ", NR=" + NR + ", intno=" + intno);
            }

            if (log.isDebugEnabled()) {
                ARM.showRegs64(u, null);
            }

            Cpsr.getArm64(u).setCarry(false);
            switch (NR) {
                case -3888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mach_absolute_time(emulator));
                    return;
                case -10:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_allocate_trap(emulator));
                    return;
                case -12:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_deallocate_trap(emulator));
                    return;
                case -15:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_map_trap(emulator));
                    return;
                case -18:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_deallocate_trap(emulator));
                    return;
                case -19:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_mod_refs_trap(emulator));
                    return;
                case -24:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_construct_trap(emulator));
                    return;
                case -26: // mach_port_t mach_reply_port(...)
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, mach_reply_port());
                    return;
                case -27:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, thread_self_trap());
                    return;
                case -28: // mach_port_name_t task_self_trap(void)
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, task_self_trap());
                    return;
                case -29:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, host_self_trap());
                    return;
                case -31:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, mach_msg_trap(emulator));
                    return;
                case -6188:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, thread_switch(emulator));
                    return;
                case 4888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, write(u, emulator));
                    return;
                case 6888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, close(u, emulator));
                    return;
                case 1088:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, unlink(emulator));
                    return;
                case 20:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, getpid(emulator));
                    return;
                case 24: // getuid
                case 25: // geteuid
                case 43: // getegid
                case 47: // getgid
                    u.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 3388:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, access(u, emulator));
                    return;
                case 4688:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sigaction(u, emulator));
                    return;
                case 48:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sigprocmask(u, emulator));
                    return;
                case 7388:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, munmap(u, emulator));
                    return;
                case 74:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, mprotect(u, emulator));
                    return;
                case 92:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, fcntl(u, emulator));
                    return;
                case 97:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, socket(u, emulator));
                    return;
                case 98:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, connect(u, emulator));
                    return;
                case 116:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, gettimeofday(emulator));
                    return;
                case 133:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sendto(u, emulator));
                    return;
                case 19488:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getrlimit(u, emulator));
                    return;
                case 197:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, mmap(u, emulator));
                    return;
                case 19988:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, lseek(u, emulator));
                    return;
                case 202:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sysctl(emulator));
                    return;
                case 305:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_cvwait(emulator));
                    return;
                case 307:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_rw_wrlock(emulator));
                    return;
                case 308:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_rw_unlock(emulator));
                    return;
                case 327:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, issetugid());
                    return;
                case 32988:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, pthread_sigmask(emulator));
                    return;
                case 33688:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, proc_info(emulator));
                    return;
                case 33888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, stat64(emulator));
                    return;
                case 339:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, fstat(u, emulator));
                    return;
                case 34488:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getdirentries64(u, emulator));
                    return;
                case 34688:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fstatfs64(u, emulator));
                    return;
                case 357:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, getaudit_addr(emulator));
                    return;
                case 366:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, bsdthread_register(emulator));
                    return;
                case 372:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, thread_selfid());
                    return;
                case 381:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sandbox_ms(emulator));
                    return;
                case 396:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, read_NOCANCEL(emulator));
                    return;
                case 397:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, write_NOCANCEL(emulator));
                    return;
                case 398:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, open_NOCANCEL(emulator));
                    return;
                case 399:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, close_NOCANCEL(emulator));
                    return;
                case 42388:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, semwait_signal_nocancel());
                    return;
                case 428:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, audit_session_self());
                    return;
                case 0x80000008:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, semaphore_signal_trap(emulator));
                    return;
                case 0x80000000:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, pthread_set_self(emulator));
                    return;
                default:
                    break;
            }
        } catch (StopEmulatorException e) {
            u.emu_stop();
            return;
        } catch (UnsupportedOperationException e) {
            exception = e;
        } catch (Throwable e) {
            u.emu_stop();
            exception = e;
        }

        Module module = emulator.getMemory().findModuleByAddress(pc.peer);
        log.warn("handleInterrupt intno=" + intno + ", NR=" + NR + ", svcNumber=0x" + Integer.toHexString(svcNumber) + ", PC=" + pc + ", syscall=" + syscall + (module == null ? "" : (", module=" + module + ", address=0x" + Long.toHexString(pc.peer - module.base))), exception);

        if (exception instanceof UnicornException) {
            throw (UnicornException) exception;
        }
    }

    private int pthread_set_self(Emulator emulator) {
        // TODO: implement
        Pointer self = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        log.info("pthread_set_self=" + self);
        return 0;
    }

    private int thread_switch(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        int thread_name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int option = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int option_time = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        log.info("thread_switch thread_name=" + thread_name + ", option=" + option + ", option_time=" + option_time);
        return 0;
    }

    private long psynch_rw_unlock(Emulator emulator) {
        // TODO: implement
        log.info("psynch_rw_unlock");
        return 0;
    }

    private long psynch_rw_wrlock(Emulator emulator) {
        // TODO: implement
        log.info("psynch_rw_wrlock");
        return 0;
    }

    private int psynch_cvwait(Emulator emulator) {
        // TODO: implement
        log.info("psynch_cvwait");
        return 0;
    }

    private int close(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close fd=" + fd);
        }

        FileIO file = fdMap.remove(fd);
        if (file != null) {
            file.close();
            return 0;
        } else {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
    }

    private int lseek(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int r1 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        long r2 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long offset = r1 | (r2 << 32);
        int whence = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        FileIO file = fdMap.get(fd);
        if (file == null) {
            if (log.isDebugEnabled()) {
                log.debug("lseek fd=" + fd + ", offset=" + offset + ", whence=" + whence);
            }
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int pos = file.lseek((int) offset, whence);
        if (log.isDebugEnabled()) {
            log.debug("lseek fd=" + fd + ", offset=" + offset + ", whence=" + whence + ", pos=" + pos);
        }
        return pos;
    }

    private int unlink(Emulator emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        String path = FilenameUtils.normalize(pathname.getString(0));
        log.info("unlink path=" + path);
        return 0;
    }

    private int getdirentries64(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int bufSize = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        Pointer basep = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        if (log.isDebugEnabled()) {
            log.debug("getdirentries64 fd=" + fd + ", buf=" + buf + ", bufSize=" + bufSize + ", basep=" + basep);
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int fstatfs64(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("fstatfs64 fd=" + fd + ", buf=" + buf);
        }
        FileIO io = fdMap.get(fd);
        if (io != null) {
            return io.fstatfs(new StatFS(buf));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int access(Unicorn u, Emulator emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("access pathname=" + path + ", mode=" + mode);
        }
        int ret = faccessat(emulator, path);
        if (ret == -1) {
            log.info("access pathname=" + path + ", mode=" + mode);
        }
        return ret;
    }

    private int faccessat(Emulator emulator, String pathname) {
        FileIO io = resolve(emulator, pathname, FileIO.O_RDONLY);
        if (io != null) {
            return 0;
        }

        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int stat64(Emulator emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, path, statbuf);
    }

    @Override
    protected int stat64(Emulator emulator, String pathname, Pointer statbuf) {
        FileIO io = resolve(emulator, pathname, FileIO.O_RDONLY);
        if (io != null) {
            return io.fstat(emulator, new Stat(statbuf));
        }

        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int write_NOCANCEL(Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer buffer = context.getPointerArg(1);
        int count = context.getIntArg(2);
        return write(emulator, fd, buffer, count);
    }

    private int fstat(Unicorn u, Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer stat = context.getPointerArg(1);
        return fstat(emulator, fd, stat);
    }

    private static final int RLIMIT_NOFILE = 8;		/* number of open files */
    private static final int RLIMIT_POSIX_FLAG = 0x1000;	/* Set bit for strict POSIX */

    private int getrlimit(Unicorn u, Emulator emulator) {
        int resource = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer rlp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        boolean posix = (resource & RLIMIT_POSIX_FLAG) != 0;
        int type = resource & (RLIMIT_POSIX_FLAG - 1);
        if (type == RLIMIT_NOFILE) {
            if (log.isDebugEnabled()) {
                log.debug("getrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type);
            }
            RLimit rLimit = new RLimit(rlp);
            rLimit.rlim_cur = 128;
            rLimit.rlim_max = 256;
            rLimit.pack();
            return 0;
        } else {
            log.info("getrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type);
        }
        return 1;
    }

    private long _kernelrpc_mach_port_mod_refs_trap(Emulator emulator) {
        Arm64RegisterContext context = emulator.getContext();
        int task = context.getXInt(0);
        int name = context.getXInt(1);
        int right = context.getXInt(2);
        int delta = context.getXInt(3);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_mod_refs_trap task=" + task + ", name=" + name + ", right=" + right + ", delta=" + delta);
        }
        return 0;
    }

    private int _kernelrpc_mach_port_construct_trap(Emulator emulator) {
        Arm64RegisterContext context = emulator.getContext();
        int task = context.getXInt(0);
        Pointer options = context.getXPointer(1);
        long ctx = context.getXInt(2);
        Pointer name = context.getXPointer(3);
        if (log.isDebugEnabled()) {
            MachPortOptions portOptions = new MachPortOptions(options);
            portOptions.unpack();
            log.debug("_kernelrpc_mach_port_construct_trap task=" + task + ", options=" + options + ", context=0x" + Long.toHexString(ctx) + ", name=" + name + ", portOptions=" + portOptions);
        }
        name.setInt(0, 0x88);
        return 0;
    }

    private long getaudit_addr(Emulator emulator) {
        Arm64RegisterContext context = emulator.getContext();
        Pointer addr = context.getXPointer(0);
        int size = context.getXInt(1);
        if (log.isDebugEnabled()) {
            log.debug("getaudit_addr=" + addr + ", size=" + size);
        }
        return 0;
    }

    private static final int PROC_INFO_CALL_SETCONTROL = 0x5;
    private static final int PROC_SELFSET_THREADNAME = 2;

    private int proc_info(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int callNum = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int pid = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int flavor = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long r4 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        long arg = r3 | (r4 << 32);
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R5);
        int bufferSize = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();

        String msg = "proc_info callNum=" + callNum + ", pid=" + pid + ", flavor=" + flavor + ", arg=" + arg + ", buffer=" + buffer + ", bufferSize=" + bufferSize;
        if (PROC_INFO_CALL_SETCONTROL == callNum && PROC_SELFSET_THREADNAME == flavor) {
            String threadName = buffer.getString(0);
            log.debug(msg);
            ((Dyld) emulator.getDlfcn()).pthread_setname_np(threadName);
            return 0;
        } else {
            log.info(msg);
            return 1;
        }
    }

    private int semwait_signal_nocancel() {
        // TODO: implement
        log.info("semwait_signal_nocancel");
        return 0;
    }

    private int pthread_sigmask(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int how = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer set = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oset = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("pthread_sigmask how=" + how + ", set=" + set + ", oset=" + oset);
        }
        return 0;
    }

    private int sandbox_ms(Emulator emulator) {
        RegisterContext context = emulator.getContext();
        Pointer policyName = context.getPointerArg(0);
        int call = context.getIntArg(1);
        Pointer args = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("sandbox_ms policyName=" + policyName.getString(0) + ", call=" + call + ", args=" + args);
        }
        return 0;
    }

    private int issetugid() {
        log.debug("issetugid");
        return 0;
    }

    private int bsdthread_register(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        UnicornPointer thread_start = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        UnicornPointer start_wqthread = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        int PTHREAD_SIZE = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        UnicornPointer data = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
        int dataSize = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X4)).intValue();
        long offset = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X5)).longValue();
        if (log.isDebugEnabled()) {
            log.debug("bsdthread_register thread_start=" + thread_start + ", start_wqthread=" + start_wqthread + ", PTHREAD_SIZE=" + PTHREAD_SIZE + ", data=" + data + ", dataSize=" + dataSize + ", offset=0x" + Long.toHexString(offset));
        }
        return 0;
    }

    private int semaphore_signal_trap(Emulator emulator) {
        Pointer sema = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        if (log.isDebugEnabled()) {
            log.debug("semaphore_signal_trap sema=" + sema);
        }
        return 0;
    }

    private int munmap(Unicorn u, Emulator emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
        int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int ret = emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x" + Long.toHexString(start) + ", length=" + length + ", ret=" + ret + ", offset=" + (System.currentTimeMillis() - timeInMillis));
        }
        return ret;
    }

    private static final int CTL_UNSPEC = 0; /* unused */
    private static final int CTL_KERN = 1; /* "high kernel": proc, limits */
    private static final int CTL_HW = 6; /* generic cpu/io */

    private static final int KERN_OSRELEASE = 2; /* string: system release */
    private static final int KERN_ARGMAX = 8; /* int: max arguments to exec */
    private static final int KERN_PROC = 14; /* struct: process entries */
    private static final int KERN_USRSTACK32 = 35; /* int: address of USRSTACK */
    private static final int KERN_PROCARGS2 = 49;
    private static final int KERN_OSVERSION = 65; /* for build number i.e. 9A127 */

    private static final int HW_PAGESIZE = 7; /* int: software page size */

    private static final int KERN_PROC_PID = 1; /* by process id */

    private int sysctl(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        Pointer name = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        int namelen = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
        Pointer bufferSize = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
        Pointer set0 = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
        int set1 = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X5)).intValue();

        int top = name.getInt(0);
        switch (top) {
            case CTL_UNSPEC:
                int action = name.getInt(4);
                if (action == 3) {
                    String sub = set0.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("sysctl CTL_UNSPEC action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", sub=" + sub);
                    }
                    if ("kern.osrelease".equals(sub)) {
                        buffer.setInt(0, CTL_KERN);
                        buffer.setInt(4, KERN_OSRELEASE);
                        bufferSize.setInt(0, 8);
                        return 0;
                    }
                    return 1;
                }
                log.info("sysctl CTL_UNSPEC action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1);
                break;
            case CTL_KERN:
                action = name.getInt(4);
                String msg = "sysctl CTL_KERN action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                switch (action) {
                    case KERN_USRSTACK32:
                    case KERN_PROCARGS2:
                        log.debug(msg);
                        return 1;
                    case KERN_OSRELEASE:
                        log.debug(msg);
                        String osRelease = "7.1.2";
                        if (bufferSize != null) {
                            bufferSize.setInt(0, osRelease.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osRelease);
                        }
                        return 0;
                    case KERN_ARGMAX:
                        bufferSize.setInt(0, 4);
                        buffer.setInt(0, 128);
                        return 0;
                    case KERN_PROC:
                        int subType = name.getInt(8);
                        if (subType == KERN_PROC_PID) {
                            int pid = name.getInt(0xc);
                            log.info(msg + ", subType=" + subType + ", pid=" + pid);
//                            emulator.attach().debug(emulator);
                            return 1;
                        }
                        log.info(msg + ", subType=" + subType);
                        break;
                    case KERN_OSVERSION:
                        log.debug(msg);
                        String osVersion = "9A127";
                        if (bufferSize != null) {
                            bufferSize.setInt(0, osVersion.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osVersion);
                        }
                        return 0;
                    default:
                        log.info(msg);
                        break;
                }
                break;
            case CTL_HW:
                action = name.getInt(4);
                msg = "sysctl CTL_HW action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                if (action == HW_PAGESIZE) {
                    log.debug(msg);
                    if (bufferSize != null) {
                        bufferSize.setInt(0, 4);
                    }
                    if (buffer != null) {
                        buffer.setInt(0, emulator.getPageAlign());
                    }
                    return 0;
                }
                log.info(msg);
                break;
            default:
                log.info("sysctl top=" + name.getInt(0) + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1);
                break;
        }
        return 1;
    }

    private int _kernelrpc_mach_vm_deallocate_trap(Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int target = context.getIntArg(0);
        long address = context.getLongArg(1);
        long size = context.getLongArg(2);

        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size));
        } else {
            Log log = LogFactory.getLog("cn.banny.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
            }
        }
        if (size > 0) {
            emulator.getMemory().munmap(address, (int) size);
        }
        return 0;
    }

    private int _kernelrpc_mach_vm_map_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        Pointer address = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        long size = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X2)).longValue();
        long mask = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X3)).longValue();
        int flags = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X4)).intValue();
        int cur_protection = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X5)).intValue();
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            throw new UnicornException("_kernelrpc_mach_vm_map_trap fixed");
        }

        MachOLoader loader = (MachOLoader) emulator.getMemory();
        Pointer value = address.getPointer(0);
        UnicornPointer pointer;
        if (mask != 0) {
            pointer = UnicornPointer.pointer(emulator, loader.allocate(size, mask));
        } else {
            pointer = loader.mmap((int) size, cur_protection);
        }
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_map_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", mask=0x" + Long.toHexString(mask) + ", flags=0x" + Long.toHexString(flags) + ", cur_protection=" + cur_protection + ", pointer=" + pointer + ", anywhere=" + anywhere + ", tag=0x" + Integer.toHexString(tag));
        } else {
            Log log = LogFactory.getLog("cn.banny.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_map_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", mask=0x" + Long.toHexString(mask) + ", flags=0x" + Long.toHexString(flags) + ", cur_protection=" + cur_protection + ", pointer=" + pointer + ", anywhere=" + anywhere + ", tag=0x" + Integer.toHexString(tag));
            }
        }
        address.setPointer(0, pointer);
        return 0;
    }

    private int _kernelrpc_mach_vm_allocate_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        Pointer address = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        long size = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X2)).longValue();
        int flags = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            throw new UnicornException("_kernelrpc_mach_vm_allocate_trap fixed");
        }

        Pointer value = address.getPointer(0);
        UnicornPointer pointer = emulator.getMemory().mmap((int) size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
        pointer.write(0, new byte[(int) size], 0, (int) size);
        address.setPointer(0, pointer);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_allocate_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", flags=0x" + Integer.toHexString(flags) + ", pointer=" + pointer + ", anywhere=" + anywhere + ", tag=0x" + Integer.toHexString(tag));
        } else {
            Log log = LogFactory.getLog("cn.banny.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_allocate_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", flags=0x" + Integer.toHexString(flags) + ", pointer=" + pointer + ", anywhere=" + anywhere + ", tag=0x" + Integer.toHexString(tag));
            }
        }
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        int name = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_deallocate_trap task=" + task + ", name=" + name);
        }
        return 0;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/thread.go
    private int thread_selfid() {
        log.debug("thread_selfid");
        return 1;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/ports.go
    private int mach_msg_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        UnicornPointer msg = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        int option = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        int send_size = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        int rcv_size = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
        int rcv_name = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X4)).intValue();
        int timeout = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X5)).intValue();
        int notify = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_X6)).intValue();

        msg.setSize(rcv_size);

        final MachMsgHeader header = new MachMsgHeader(msg);
        header.unpack();
        if (log.isDebugEnabled()) {
            log.debug("mach_msg_trap msg=" + msg + ", option=0x" + Integer.toHexString(option) + ", send_size=" + send_size + ", rcv_size=" + rcv_size + ", rcv_name=" + rcv_name + ", timeout=" + timeout + ", notify=" + notify + ", header=" + header);
        }

        final Pointer request = msg.share(header.size());

        switch (header.msgh_id) {
            case 3409: // task_get_special_port
            {
                TaskGetSpecialPortRequest args = new TaskGetSpecialPortRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_get_special_port request=" + args);
                }

                switch (args.which) {
                    case TASK_BOOTSTRAP_PORT:
                        TaskGetSpecialPortReply reply = new TaskGetSpecialPortReply(request);
                        reply.unpack();

                        header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                        header.msgh_size = header.size() + reply.size();
                        header.msgh_remote_port = header.msgh_local_port;
                        header.msgh_local_port = 0;
                        header.msgh_id += 100; // reply Id always equals reqId+100
                        header.pack();

                        reply.body.msgh_descriptor_count = 1;
                        reply.port.name = BOOTSTRAP_PORT; // I just chose 11 randomly here
                        reply.port.pad1 = 0;
                        reply.port.pad2 = 0;
                        reply.port.disposition = 17; // meaning?
                        reply.port.type = MACH_MSG_PORT_DESCRIPTOR;
                        reply.pack();
                        if (log.isDebugEnabled()) {
                            log.debug("task_get_special_port reply=" + reply);
                        }

                        return MACH_MSG_SUCCESS;
                }
            }
            case 200: // host_info
            {
                HostInfoRequest args = new HostInfoRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_info args=" + args);
                }

                switch (args.flavor) {
                    case HOST_PRIORITY_INFO:
                        HostInfoReply reply = new HostInfoReply(request);
                        reply.unpack();

                        header.msgh_bits &= 0xff;
                        header.msgh_size = header.size() + reply.size();
                        header.msgh_remote_port = header.msgh_local_port;
                        header.msgh_local_port = 0;
                        header.msgh_id += 100; // reply Id always equals reqId+100
                        header.pack();

                        reply.NDR = args.NDR;
                        reply.retCode = 0; // success
                        reply.host_info_outCnt = 8;
                        reply.host_info_out.kernel_priority = 0;
                        reply.host_info_out.system_priority = 0;
                        reply.host_info_out.server_priority = 0;
                        reply.host_info_out.user_priority = 0;
                        reply.host_info_out.depress_priority = 0;
                        reply.host_info_out.idle_priority = 0;
                        reply.host_info_out.minimum_priority = 10;
                        reply.host_info_out.maximum_priority = -10;
                        reply.pack();

                        if (log.isDebugEnabled()) {
                            log.debug("host_info reply=" + reply);
                        }
                        return MACH_MSG_SUCCESS;
                }
            }
            case 206: // host_get_clock_service
            {
                HostGetClockServiceRequest args = new HostGetClockServiceRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_get_clock_service args=" + args);
                }

                HostGetClockServiceReply reply = new HostGetClockServiceReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.clock_server.name = CLOCK_SERVER_PORT; // I just chose 13 randomly here
                reply.clock_server.pad1 = 0;
                reply.clock_server.pad2 = 0;
                reply.clock_server.disposition = 17; // meaning?
                reply.clock_server.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();
                if (log.isDebugEnabled()) {
                    log.debug("host_get_clock_service reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3418: // semaphore_create
            {
                SemaphoreCreateRequest args = new SemaphoreCreateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("semaphore_create args=" + args);
                }

                SemaphoreCreateReply reply = new SemaphoreCreateReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.semaphore.name = SEMAPHORE_PORT; // I just chose 14 randomly here
                reply.semaphore.pad1 = 0;
                reply.semaphore.pad2 = 0;
                reply.semaphore.disposition = 17; // meaning?
                reply.semaphore.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();
                if (log.isDebugEnabled()) {
                    log.debug("semaphore_create reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3822: // vm_region_recurse_64
            {
                VmRegionRecurse64Request args = new VmRegionRecurse64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 args=" + args);
                }

                VmRegionRecurse64Reply reply = new VmRegionRecurse64Reply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                MemoryMap memoryMap = null;
                for (MemoryMap mm : emulator.getMemory().getMemoryMap()) {
                    if (args.address >= mm.base && args.address < mm.base + mm.size) {
                        memoryMap = mm;
                        break;
                    }
                }

                if (memoryMap == null) {
                    break;
                }

                reply.NDR = args.NDR;
                reply.retCode = 0; // success
                reply.address = (int) memoryMap.base;
                reply.size = (int) memoryMap.size;
                reply.infoCnt = args.infoCnt;
                reply.nestingDepth = args.nestingDepth;
                reply.info.protection = memoryMap.prot;
                reply.info.max_protection = memoryMap.prot;
                reply.info.inheritance = memoryMap.prot;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 reply=" + reply + ", memoryMap=" + memoryMap);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3414: // task_get_exception_ports
            {
                TaskGetExceptionPortsRequest args = new TaskGetExceptionPortsRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_get_exception_ports args=" + args + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                TaskGetExceptionPortsReply reply = new TaskGetExceptionPortsReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                args.NDR.mig_vers = 0x20;
                reply.NDR = args.NDR;
                reply.retCode = 0;
                reply.header = new int[32];
                reply.reserved = new byte[0x100];
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("task_get_exception_ports reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3404: // mach_ports_lookup
            {
                MachPortsLookupReply reply = new MachPortsLookupReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = 52;
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 1;
                reply.outPort = request;
                reply.ret = 0;
                reply.mask = 0x2110000;
                reply.cnt = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("mach_ports_lookup reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            default:
                log.warn("mach_msg_trap header=" + header + ", size=" + header.size() + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                break;
        }

        return -1;
    }

    private static final int BOOTSTRAP_PORT = 11;
    private static final int CLOCK_SERVER_PORT = 13;
    private static final int SEMAPHORE_PORT = 14;

    private int task_self_trap() {
        log.debug("task_self_trap");
        return 1;
    }

    private int host_self_trap() {
        log.debug("host_self_trap");
        return 2;
    }

    private int thread_self_trap() {
        log.debug("thread_self_trap");
        return 3;
    }

    private int mach_reply_port() {
        log.debug("mach_reply_port");
        return 4;
    }

    private long audit_session_self() {
        log.debug("audit_session_self");
        return 5;
    }

    private int sigprocmask(Unicorn u, Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int how = context.getIntArg(0);
        Pointer set = context.getPointerArg(1);
        Pointer oldset = context.getPointerArg(2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private long gettimeofday(Emulator emulator) {
        EditableArm64RegisterContext context = emulator.getContext();
        long currentTimeMillis = System.currentTimeMillis();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000;
        context.setXLong(1, tv_usec);
        if (log.isDebugEnabled()) {
            log.debug("gettimeofday");
        }
        return tv_sec;
    }

    private int mach_absolute_time(Emulator emulator) {
        long nanoTime = System.nanoTime();
        log.debug("mach_absolute_time nanoTime=" + nanoTime);
        emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (nanoTime >> 32));
        return (int) (nanoTime);
    }

    private int close_NOCANCEL(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close_NOCANCEL fd=" + fd);
        }

        FileIO file = fdMap.remove(fd);
        if (file != null) {
            file.close();
            return 0;
        } else {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
    }

    private int read_NOCANCEL(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        int count = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("read_NOCANCEL fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }
        return read(emulator, fd, buffer, count);
    }

    private int open_NOCANCEL(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        Pointer pathname_p = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        int oflags = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        int mode = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        String pathname = pathname_p.getString(0);
        int fd = open(emulator, pathname, oflags);
        if (fd == -1) {
            log.info("open_NOCANCEL pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode));
        } else if (log.isDebugEnabled()) {
            log.debug("open_NOCANCEL pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode) + ", fd=" + fd);
        }
        return fd;
    }

    private int getpid(Emulator emulator) {
        int pid = emulator.getPid();
        log.debug("getpid pid=" + pid);
        return pid;
    }

    private int sendto(Unicorn u, Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        int len = context.getIntArg(2);
        int flags = context.getIntArg(3);
        Pointer dest_addr = context.getPointerArg(4);
        int addrlen = context.getIntArg(5);

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Unicorn u, Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        int addrlen = context.getIntArg(2);
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int sigaction(Unicorn u, Emulator emulator) {
        int signum = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer act = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldact = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);

        return sigaction(signum, act, oldact);
    }

    private int fcntl(Unicorn u, Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int cmd = context.getIntArg(1);
        int arg = context.getIntArg(2);
        return fcntl(emulator, fd, cmd, arg);
    }

    private long mmap(Unicorn u, Emulator emulator) {
        Arm64RegisterContext context = emulator.getContext();
        UnicornPointer addr = context.getXPointer(0);
        int length = context.getXInt(1);
        int prot = context.getXInt(2);
        int flags = context.getXInt(3);
        int fd = context.getXInt(4);
        long offset = context.getXLong(5);

        int tag = fd >>> 24;
        if (tag != 0) {
            fd = -1;
        }

        boolean warning = length >= 0x10000000;
        long base = emulator.getMemory().mmap2(addr == null ? 0 : addr.peer, length, prot, flags, fd, (int) offset);
        String msg = "mmap addr=" + addr + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset + ", tag=" + tag;
        if (log.isDebugEnabled() || warning) {
            if (warning) {
                log.warn(msg);
            } else {
                log.debug(msg);
            }
        } else {
            Log log = LogFactory.getLog("cn.banny.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(msg + ", base=0x" + Long.toHexString(base));
            }
        }
        return base;
    }

    private int socket(Unicorn u, Emulator emulator) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(0);
        int type = context.getIntArg(1) & 0x7ffff;
        int protocol = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("socket domain=" + domain + ", type=" + type + ", protocol=" + protocol);
        }

        if (protocol == SocketIO.IPPROTO_ICMP) {
            throw new UnsupportedOperationException();
        }

        int fd;
        switch (domain) {
            case SocketIO.AF_UNSPEC:
                throw new UnsupportedOperationException();
            case SocketIO.AF_LOCAL:
                switch (type) {
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new LocalDarwinUdpSocket(emulator));
                        return fd;
                    default:
                        emulator.getMemory().setErrno(UnixEmulator.EACCES);
                        return -1;
                }
            case SocketIO.AF_INET:
            case SocketIO.AF_INET6:
                switch (type) {
                    case SocketIO.SOCK_STREAM:
                        fd = getMinFd();
                        fdMap.put(fd, new TcpSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new UdpSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_RAW:
                        throw new UnsupportedOperationException();
                }
                break;
        }
        throw new UnsupportedOperationException("socket domain=" + domain + ", type=" + type + ", protocol=" + protocol);
    }

    private int write(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        byte[] data = buffer.getByteArray(0, count);
        if (log.isDebugEnabled()) {
            Inspector.inspect(data, "write fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.write(data);
    }

    private int mprotect(Unicorn u, Emulator emulator) {
        long address = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
        long length = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).longValue();
        int prot = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        long alignedAddress = address / ARMEmulator.PAGE_ALIGN * ARMEmulator.PAGE_ALIGN; // >> 12 << 12;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x" + Long.toHexString(address) + ", alignedAddress=0x" + Long.toHexString(alignedAddress) + ", offset=" + offset + ", length=" + length + ", alignedLength=" + alignedLength + ", prot=0x" + Integer.toHexString(prot));
        }
        return emulator.getMemory().mprotect(alignedAddress, (int) alignedLength, prot);
    }

}
