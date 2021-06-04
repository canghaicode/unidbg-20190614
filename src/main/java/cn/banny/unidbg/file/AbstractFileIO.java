package cn.banny.unidbg.file;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.ios.struct.kernel.StatFS;
import cn.banny.unidbg.memory.MemoryMap;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Map;

public abstract class AbstractFileIO implements FileIO {

    private static final int F_GETFD = 1; /* get file descriptor flags */
    private static final int F_SETFD = 2; /* set file descriptor flags */
    private static final int F_GETFL = 3; /* get file status flags */
    private static final int F_SETFL = 4; /* set file status flags */
    private static final int F_SETLK = 6; /* Set record locking info (non-blocking).  */
    private static final int F_SETLKW = 7; /* Set record locking info (blocking).	*/
    private static final int F_ADDFILESIGS = 61; /* add signature from same file (used by dyld for shared libs) */

    private static final int FD_CLOEXEC = 1;

    protected int op;
    protected int oflags;

    protected AbstractFileIO(int oflags) {
        this.oflags = oflags;
    }

    @Override
    public int fcntl(int cmd, int arg) {
        switch (cmd) {
            case F_GETFD:
                return op;
            case F_SETFD:
                if (FD_CLOEXEC == arg) {
                    op |= FD_CLOEXEC;
                    return 0;
                }
                break;
            case F_GETFL:
                return oflags;
            case F_SETFL:
                if ((O_APPEND & arg) != 0) {
                    oflags |= O_APPEND;
                }
                if ((O_RDWR & arg) != 0) {
                    oflags |= O_RDWR;
                }
                if ((O_NONBLOCK & arg) != 0) {
                    oflags |= O_NONBLOCK;
                }
                return 0;
            case F_SETLK:
            case F_SETLKW:
            case F_ADDFILESIGS:
                return 0;
        }
        throw new UnsupportedOperationException(getClass().getName() + ", cmd=" + cmd + ", arg=0x" + Long.toHexString(arg & 0xffffffffL));
    }

    @Override
    public int ioctl(Emulator emulator, long request, long argp) {
        throw new AbstractMethodError(getClass().getName() + ": request=0x" + Long.toHexString(request) + ", argp=0x" + Long.toHexString(argp));
    }

    @Override
    public int connect(Pointer addr, int addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int setsockopt(int level, int optname, Pointer optval, int optlen) {
        throw new AbstractMethodError();
    }

    @Override
    public int getsockopt(int level, int optname, Pointer optval, Pointer optlen) {
        throw new AbstractMethodError(getClass().getName() + ": level=" + level + ", optname=" + optname + ", optval=" + optval + ", optlen=" + optlen);
    }

    @Override
    public int getsockname(Pointer addr, Pointer addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen) {
        throw new AbstractMethodError(Inspector.inspectString(data, "sendto flags=0x" + Integer.toHexString(flags) + ", dest_addr=" + dest_addr + ", addrlen=" + addrlen));
    }

    @Override
    public int recvfrom(Unicorn unicorn, Pointer buf, int len, int flags, Pointer src_addr, Pointer addrlen) {
        throw new AbstractMethodError(getClass().getName() + ": recvfrom buf=" + buf + ", len=" + len + ", flags=0x" + Integer.toHexString(flags) + ", src_addr=" + src_addr + ", addrlen=" + addrlen);
    }

    @Override
    public int lseek(int offset, int whence) {
        throw new AbstractMethodError("class=" + getClass());
    }

    @Override
    public int ftruncate(int length) {
        throw new AbstractMethodError();
    }

    @Override
    public int getpeername(Pointer addr, Pointer addrlen) {
        throw new AbstractMethodError();
    }

    @Override
    public int shutdown(int how) {
        throw new AbstractMethodError();
    }

    @Override
    public final long mmap2(Unicorn unicorn, long addr, int aligned, int prot, int offset, int length, Map<Long, MemoryMap> memoryMap) throws IOException {
        byte[] data = getMmapData(offset, length);
        unicorn.mem_map(addr, aligned, prot);
        memoryMap.put(addr, new MemoryMap(addr, aligned, prot));
        unicorn.mem_write(addr, data);
        return addr;
    }

    protected byte[] getMmapData(int offset, int length) throws IOException {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int llseek(long offset_high, long offset_low, Pointer result, int whence) {
        throw new AbstractMethodError();
    }

    @Override
    public int getdents64(Pointer dirp, int count) {
        throw new AbstractMethodError();
    }

    @Override
    public void close() {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int write(byte[] data) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        throw new AbstractMethodError();
    }

    @Override
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int fstat(Emulator emulator, StatStructure stat) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int fstatfs(StatFS statFS) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public FileIO dup2() {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public String getPath() {
        throw new AbstractMethodError(getClass().getName());
    }
}
