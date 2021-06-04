package cn.banny.unidbg.linux.file;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.file.AbstractFileIO;
import cn.banny.unidbg.file.FileIO;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Arrays;

public class Stdin extends AbstractFileIO implements FileIO {

    public Stdin(int oflags) {
        super(oflags);
    }

    @Override
    public void close() {
    }

    @Override
    public int write(byte[] data) {
        throw new AbstractMethodError();
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        try {
            byte[] data = new byte[count];
            int read = System.in.read(data, 0, count);
            if (read <= 0) {
                return read;
            }

            buffer.write(0, Arrays.copyOf(data, read), 0, read);
            return read;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        stat.setInt(0x10, 0); // st_mode
        stat.setLong(0x30, 0); // st_size
        return 0;
    }

    @Override
    public FileIO dup2() {
        return this;
    }

    @Override
    public int ioctl(Emulator emulator, long request, long argp) {
        return 0;
    }
}
